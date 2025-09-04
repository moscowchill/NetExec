![Supported Python versions](https://img.shields.io/badge/python-3.10+-blue.svg)
[![Twitter](https://img.shields.io/twitter/follow/al3xn3ff?label=al3x_n3ff&style=social)](https://twitter.com/intent/follow?screen_name=al3x_n3ff)
[![Twitter](https://img.shields.io/twitter/follow/_zblurx?label=_zblurx&style=social)](https://twitter.com/intent/follow?screen_name=_zblurx)
[![Twitter](https://img.shields.io/twitter/follow/MJHallenbeck?label=MJHallenbeck&style=social)](https://twitter.com/intent/follow?screen_name=MJHallenbeck)
[![Twitter](https://img.shields.io/twitter/follow/mpgn_x64?label=mpgn_x64&style=social)](https://twitter.com/intent/follow?screen_name=mpgn_x64)


🚩 This is the open source repository of NetExec maintained by a community of passionate people
# NetExec - The Network Execution Tool

This project was initially created in 2015 by @byt3bl33d3r, known as CrackMapExec. In 2019 @mpgn_x64 started maintaining the project for the next 4 years, adding a lot of great tools and features. In September 2023 he retired from maintaining the project.

Along with many other contributors, we (NeffIsBack, Marshall-Hallenbeck, and zblurx) developed new features, bug fixes, and helped maintain the original project CrackMapExec.
During this time, with both a private and public repository, community contributions were not easily merged into the project. The 6-8 month discrepancy between the code bases caused many development issues and heavily reduced community-driven development.
With the end of mpgn's maintainer role, we (the remaining most active contributors) decided to maintain the project together as a fully free and open source project under the new name **NetExec** 🚀
Going forward, our intent is to maintain a community-driven and maintained project with regular updates for everyone to use.

<p align="center">
  <!-- placeholder for nxc logo-->
</p>

You are on the **latest up-to-date** repository of the project NetExec (nxc) ! 🎉

- 🚧 If you want to report a problem, open an [Issue](https://github.com/Pennyw0rth/NetExec/issues) 
- 🔀 If you want to contribute, open a [Pull Request](https://github.com/Pennyw0rth/NetExec/pulls)
- 💬 If you want to discuss, open a [Discussion](https://github.com/Pennyw0rth/NetExec/discussions)

## Official Discord Channel

If you don't have a Github account, you can ask your questions on Discord!

[![NetExec](https://discordapp.com/api/guilds/1148685154601160794/widget.png?style=banner3)](https://discord.gg/pjwUTQzg8R)

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

## Availability on Unix distributions

[![Packaging status](https://repology.org/badge/vertical-allrepos/netexec.svg)](https://repology.org/project/netexec/versions)

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

# Development
Development guidelines and recommendations in development

# Acknowledgments
All the hard work and development over the years from everyone in the CrackMapExec project

# Code Contributors
Awesome code contributors of NetExec:

[![](https://github.com/mpgn.png?size=50)](https://github.com/mpgn)
[![](https://github.com/Marshall-Hallenbeck.png?size=50)](https://github.com/Marshall-Hallenbeck)
[![](https://github.com/zblurx.png?size=50)](https://github.com/zblurx)
[![](https://github.com/NeffIsBack.png?size=50)](https://github.com/NeffIsBack)
[![](https://github.com/Hackndo.png?size=50)](https://github.com/Hackndo)
[![](https://github.com/XiaoliChan.png?size=50)](https://github.com/XiaoliChan)
[![](https://github.com/termanix.png?size=50)](https://github.com/termanix)
[![](https://github.com/Dfte.png?size=50)](https://github.com/Dfte)
