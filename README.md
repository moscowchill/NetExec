🚩 This is the open source repository of NetExec maintained by a community of passionate people
# NetExec - The Network Execution Tool

# Documentation, Tutorials, Examples
See the project's [wiki](https://netexec.wiki/) (in development) for documentation and usage examples

# Installation
Please see the installation instructions on the [wiki](https://netexec.wiki/getting-started/installation) (in development)

## Linux
```
sudo apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```

# Enhanced Fork Features 🚀

This fork includes additional stealth and evasion enhancements for penetration testing scenarios:

## Stealth & Evasion Features

### 🥷 Plausible Username Enumeration
- **Enhanced host enumeration** using realistic service account names instead of null sessions
- **Blends with legitimate traffic** - failed logins appear normal in logs
- **Randomized selection** from 60+ plausible usernames (svc_backup, PrinterQueue, SQLServer, etc.)
- **Bypassed with `--no-delays`** for speed when stealth isn't needed

### ⚡ Enhanced Speed Controls
- **`--no-delays` flag** - Skip all tactical delays for maximum speed
  - Direct empty credential authentication
  - Bypasses connection delays and obfuscation
  - No tactical delay countdowns
- **Optimized DNS handling** - `--local-auth` skips unnecessary KDC discovery DNS lookups

### 🎭 Command Obfuscation
- **`--nobfs` flag** - Disable command obfuscation for compatibility
- **Enhanced SMBEXEC** with multiple obfuscation techniques:
  - **Case randomization** - Commands use randomized upper/lowercase (`eCHo`, `MoVe`, `ComSpEc`)
  - **Environment variable obfuscation** - `%COMSPEC%` → `%cOmSpEc%`, `%LOCALAPPDATA%` → `%lOcAlApPdAtA%`
  - **Command flag randomization** - `/Q` → `/q`, `/C` → `/c` with random casing
  - **File operation masking** - Uses `move /y file NUL` instead of obvious `del` commands
  - **Batch file cleanup** - Automatic removal of temporary execution files
- **Plausible service names** for command execution (WinDriverSync, ChromeUpdate, etc.)
- **Tactical delays** with visual countdown timers for stealth operations

### 🔐 Advanced Admin Detection
- **Enhanced UAC detection** with detailed privilege status reporting
- **Direct RID 500 checks** for built-in Administrator identification
- **Multiple verification methods** for reliable admin privilege detection
- **Improved logging** for admin status and UAC bypass capabilities
- **Conditional checks** for Windows vs Unix environments

### 🌐 Client Hostname Spoofing
- **100+ plausible client names** for SMB connections
- **Device mimicry** - appears as printers, cameras, IoT devices, etc.
- **Network camouflage** - blends with typical corporate network traffic

## Usage Examples

```bash
# Default stealth mode - plausible usernames + full obfuscation
netexec smb 192.168.1.0/24 -u admin -p password

# Speed mode - fast enumeration but still obfuscated commands  
netexec smb 192.168.1.0/24 -u admin -p password --no-delays

# Maximum speed - bypass delays and obfuscation
netexec smb 192.168.1.0/24 -u admin -p password --no-delays --nobfs

# Command execution with obfuscation
netexec smb 192.168.1.1 -u admin -p password -x whoami
# Creates: %cOmSpEc% /q /c eCHo whoami > %lOcAlApPdAtA%\WinDriverSync_20250904.bat

# Plain command execution (compatibility mode)
netexec smb 192.168.1.1 -u admin -p password -x whoami --nobfs  
# Creates: cmd.exe /q /c echo whoami > %LOCALAPPDATA%\WinDriverSync_20250904.bat
```

## Performance Comparison

| Mode | Host Enumeration | DNS Resolution | Command Execution | Service Names |
|------|------------------|----------------|-------------------|---------------|
| **Default (Stealth)** | Plausible usernames (3-6s) | KDC discovery (domain mode) | Obfuscated (`eCHo`, `%cOmSpEc%`) | Randomized (WinDriverSync_20250904) |
| **`--local-auth`** | Plausible usernames (3-6s) | Skipped (local mode) | Obfuscated | Randomized |
| **`--no-delays`** | Empty credentials (<1s) | Based on auth mode | Obfuscated (unless `--nobfs`) | Randomized |
| **`--local-auth --no-delays`** | Empty credentials (<1s) | Skipped | Obfuscated (unless `--nobfs`) | Randomized |

---
