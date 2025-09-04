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
  - Instant DNS resolution with 1-second timeout
  - Direct empty credential authentication
  - Bypasses connection delays and obfuscation
- **Optimized DNS handling** - Uses fast public DNS (8.8.8.8) automatically with `--no-delays`

### 🎭 Command Obfuscation
- **`--nobfs` flag** - Disable command obfuscation for compatibility
- **Enhanced SMBEXEC** with configurable obfuscation settings
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
# Stealth mode with plausible usernames and delays
netexec smb 192.168.1.0/24 -u admin -p password

# Speed mode - bypass all delays and stealth features
netexec smb 192.168.1.0/24 -u admin -p password --no-delays

# Disable command obfuscation for compatibility
netexec smb 192.168.1.1 -u admin -p password --nobfs
```

## Performance Comparison

| Mode | Host Enumeration | DNS Resolution | Command Execution |
|------|------------------|----------------|-------------------|
| **Default (Stealth)** | Plausible usernames (3-6s) | Standard timeout (3s) | Obfuscated commands |
| **`--no-delays`** | Empty credentials (<1s) | Fast DNS (1s) | Direct execution |

---
