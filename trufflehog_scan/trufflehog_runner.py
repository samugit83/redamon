"""
TruffleHog Runner - Executes TruffleHog binary and parses JSONL output

Builds CLI commands from project settings, runs TruffleHog as a subprocess,
and normalizes the JSONL output into the RedAmon findings format.
"""

import json
import os
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


class TrufflehogRunner:
    """Runs TruffleHog binary and collects findings."""

    def __init__(
        self,
        token: str,
        target_org: str = "",
        target_repos: str = "",
        project_id: str = "",
        only_verified: bool = False,
        no_verification: bool = False,
        concurrency: int = 8,
        include_detectors: str = "",
        exclude_detectors: str = "",
    ):
        self.token = token
        self.target_org = target_org
        self.target_repos = target_repos
        self.project_id = project_id
        self.only_verified = only_verified
        self.no_verification = no_verification
        self.concurrency = concurrency
        self.include_detectors = include_detectors
        self.exclude_detectors = exclude_detectors

        # Output file
        self.output_dir = Path(__file__).parent / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.output_file = str(self.output_dir / f"trufflehog_{project_id}.json")

        # Statistics
        self.stats = {
            "total_findings": 0,
            "verified_findings": 0,
            "unverified_findings": 0,
            "repositories_scanned": 0,
            "detector_types": {},
        }

        # Collected findings
        self.findings: list[dict] = []
        self._seen_repos: set[str] = set()

    def _build_common_flags(self) -> list[str]:
        """Build common CLI flags for TruffleHog."""
        flags = ["--json"]

        if self.only_verified:
            flags.append("--results=verified")

        if self.no_verification:
            flags.append("--no-verification")

        if self.concurrency > 0:
            flags.extend(["--concurrency", str(self.concurrency)])

        if self.include_detectors:
            flags.extend(["--include-detectors", self.include_detectors])

        if self.exclude_detectors:
            flags.extend(["--exclude-detectors", self.exclude_detectors])

        return flags

    def _build_commands(self) -> list[list[str]]:
        """Build the TruffleHog CLI commands to execute.

        Priority: if specific repos are set, scan ONLY those repos (skip org-wide scan).
        Org-wide scan only runs when no specific repos are configured.
        """
        commands = []
        common_flags = self._build_common_flags()

        if self.target_repos:
            # Specific repos take priority — scan only these, not the whole org
            repos = [r.strip() for r in self.target_repos.split(",") if r.strip()]
            for repo in repos:
                # Ensure repo is a full URL
                if not repo.startswith("http"):
                    repo = f"https://github.com/{repo}"
                cmd = [
                    "trufflehog", "github",
                    f"--repo={repo}",
                    f"--token={self.token}",
                ] + common_flags
                commands.append(cmd)
        elif self.target_org:
            # No specific repos — scan entire organization
            cmd = [
                "trufflehog", "github",
                f"--org={self.target_org}",
                f"--token={self.token}",
            ] + common_flags
            commands.append(cmd)

        return commands

    def _extract_source_meta(self, result: dict) -> dict:
        """Extract source metadata from a TruffleHog finding.

        SourceMetadata.Data can contain Github, Git, or Filesystem keys.
        """
        source_data = result.get("SourceMetadata", {}).get("Data", {})

        # Try Github first, then Git, then Filesystem
        for key in ("Github", "Git", "Filesystem"):
            if key in source_data:
                meta = source_data[key]
                return {
                    "repository": meta.get("repository", meta.get("link", "")),
                    "file": meta.get("file", meta.get("path", "")),
                    "commit": meta.get("commit", ""),
                    "line": meta.get("line", 0),
                    "link": meta.get("link", ""),
                    "email": meta.get("email", ""),
                    "timestamp": meta.get("timestamp", ""),
                    "visibility": meta.get("visibility", 0),
                }

        return {
            "repository": "", "file": "", "commit": "", "line": 0,
            "link": "", "email": "", "timestamp": "", "visibility": 0,
        }

    def _parse_finding(self, result: dict) -> Optional[dict]:
        """Parse a single TruffleHog JSON result into normalized format."""
        try:
            source_meta = self._extract_source_meta(result)
            detector_name = result.get("DetectorName", "Unknown")

            finding = {
                "detector_name": detector_name,
                "detector_description": result.get("DetectorDescription", ""),
                "verified": result.get("Verified", False),
                "redacted": result.get("Redacted", ""),
                "raw": result.get("Raw", ""),
                "repository": source_meta["repository"],
                "file": source_meta["file"],
                "commit": source_meta["commit"],
                "line": source_meta["line"],
                "link": source_meta["link"],
                "email": source_meta["email"],
                "timestamp": source_meta["timestamp"],
                "extra_data": json.dumps(result.get("ExtraData") or {}),
            }

            # Update stats
            self.stats["total_findings"] += 1
            if finding["verified"]:
                self.stats["verified_findings"] += 1
            else:
                self.stats["unverified_findings"] += 1

            self.stats["detector_types"][detector_name] = (
                self.stats["detector_types"].get(detector_name, 0) + 1
            )

            # Track unique repos
            repo = finding["repository"]
            if repo and repo not in self._seen_repos:
                self._seen_repos.add(repo)
                self.stats["repositories_scanned"] = len(self._seen_repos)

            return finding

        except Exception as e:
            print(f"[!] Error parsing finding: {e}")
            return None

    def _run_command(self, cmd: list[str]) -> None:
        """Execute a single TruffleHog command and collect findings."""
        # Log command without token
        safe_cmd = [c if not c.startswith("--token=") else "--token=***" for c in cmd]
        print(f"[*] Running: {' '.join(safe_cmd)}")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            # Read JSONL output line by line
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    result = json.loads(line)
                    finding = self._parse_finding(result)
                    if finding:
                        self.findings.append(finding)
                        # Log each finding
                        verified_tag = " [VERIFIED]" if finding["verified"] else ""
                        print(
                            f"[+] Found: {finding['detector_name']}{verified_tag} "
                            f"in {finding['file']} ({finding['repository']})"
                        )
                        # Save incrementally
                        self._save_incremental()
                except json.JSONDecodeError:
                    # Not JSON — likely a status/progress message from TruffleHog
                    if line.strip():
                        print(f"[~] {line}")

            # Wait for process to complete
            process.wait()

            # Read stderr
            stderr_output = process.stderr.read()
            if stderr_output:
                for err_line in stderr_output.strip().split("\n"):
                    if err_line.strip():
                        print(f"[~] {err_line.strip()}")

            if process.returncode != 0:
                print(f"[!] TruffleHog exited with code {process.returncode}")

        except FileNotFoundError:
            print("[!] ERROR: trufflehog binary not found. Ensure it is installed at /usr/local/bin/trufflehog")
            raise
        except Exception as e:
            print(f"[!] Error running TruffleHog: {e}")
            raise

    def _save_incremental(self) -> None:
        """Save current results incrementally using atomic temp-file rename."""
        output_data = self._build_output()
        try:
            fd, tmp_path = tempfile.mkstemp(
                dir=str(self.output_dir), suffix=".tmp"
            )
            with os.fdopen(fd, "w") as f:
                json.dump(output_data, f, indent=2, default=str)
            os.replace(tmp_path, self.output_file)
        except Exception as e:
            print(f"[!] Error saving incremental results: {e}")

    def _build_output(self) -> dict:
        """Build the final output JSON structure."""
        return {
            "target": self.target_org or self.target_repos,
            "scan_start_time": self._start_time,
            "scan_end_time": datetime.now().isoformat(),
            "duration_seconds": round(time.time() - self._start_epoch, 2),
            "status": "in_progress",
            "statistics": self.stats.copy(),
            "findings": self.findings,
        }

    def run(self) -> list[dict]:
        """Execute TruffleHog scan and return findings."""
        self._start_time = datetime.now().isoformat()
        self._start_epoch = time.time()

        commands = self._build_commands()
        if not commands:
            print("[!] No scan targets configured")
            return []

        target_desc = self.target_org or self.target_repos
        print(f"[*] Scanning organization: {target_desc}")
        print(f"[*] Total scan commands: {len(commands)}")

        for i, cmd in enumerate(commands, 1):
            print(f"\n[*] Scanning repository set {i}/{len(commands)}...")
            self._run_command(cmd)

        # Save final results
        output_data = self._build_output()
        output_data["status"] = "completed"
        output_data["scan_end_time"] = datetime.now().isoformat()
        output_data["duration_seconds"] = round(time.time() - self._start_epoch, 2)

        with open(self.output_file, "w") as f:
            json.dump(output_data, f, indent=2, default=str)

        print(f"\n[+] Final results saved to {self.output_file}")
        return self.findings

    def save_results(self) -> str:
        """Save final results and return path."""
        return self.output_file
