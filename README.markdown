# AD-PTF: Active Directory Penetration Testing Framework

![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![GitHub Stars](https://img.shields.io/github/stars/jaberhasantaslim/AD-PTF)
![GitHub Issues](https://img.shields.io/github/issues/jaberhasantaslim/AD-PTF)

```
   ___    ____        _____            _____     _____    _____    _____ 
  / _ \  |  _ \      |  ___|   ___    |  ___|   /  _  \  |  ___|  /  _  \
 / /_\ \ | | | |____ | |__    / _ \   | |__    | | | |  | |__    | | | |
/ _____ \| | | |____||  __|  | | | |  |  __|   | | | |  |  __|   | | | |
/ /   \ \| |_/ /     | |___  | |_| |  | |___   | |_| |  | |___   | |_| |
\/     \/|____/      |_____|  \___/   |_____|   \_____/  |_____|  \_____/
                                                                        
Active Directory Penetration Testing Framework v2.0
Author: Jaber Hasan
```

## Overview

**AD-PTF** (Active Directory Penetration Testing Framework) is a Python-based tool designed to automate the installation and execution of Active Directory (AD) attack tools for authorized penetration testing. It streamlines network discovery, AD enumeration, vulnerability assessment, password attacks, exploitation, and post-exploitation, generating minimal attack reports for analysis.

> **⚠️ WARNING**: This tool is for **authorized penetration testing only**. Ensure you have explicit permission from the target system's owner before use. Unauthorized use may violate laws and ethical guidelines.

## Features

- **Automated Tool Installation**: Installs AD attack tools like `nmap`, `masscan`, `bloodhound`, `ldapsearch`, `hydra`, and more.
- **Network Discovery**: Scans networks with customizable ports and scan intensity (Aggressive or Stealth).
- **AD Enumeration**: Identifies users, groups, and configurations using `smbclient`, `ldapdomaindump`, and `windapsearch`.
- **Vulnerability Assessment**: Detects vulnerabilities like SMBGhost, EternalBlue, Zerologon, and PrintNightmare.
- **Password Attacks**: Supports password spraying and cracking with `hydra`, `kerbrute`, and `hashcat`.
- **Exploitation**: Executes exploits like PetitPotam, PrintNightmare, and Golden Ticket attacks.
- **Post-Exploitation**: Facilitates privilege escalation and lateral movement with `BloodHound`, `PowerView`, and `PlumHound`.
- **Anonymous Mode**: Uses `proxychains4` for anonymized testing via Tor or other proxies.
- **Interactive Menu**: User-friendly interface for setup, testing, and troubleshooting via `tgpt`.
- **Report Generation**: Saves results to `~/AD-PenTest-Results` with a summary report and zipped archive.

## Requirements

- **Operating System**: Linux (tested on Kali Linux)
- **Python**: 3.6 or higher
- **System Dependencies**:
  - Binaries: `masscan`, `nmap`, `ldapsearch`, `smbclient`, `rpcclient`, `hydra`, `proxychains`, `hashcat`, `go`, `ruby`, `wine`, `wine32`
  - Git Repositories: `impacket`, `PlumHound`, `Responder`, `windapsearch`, `CVE-2020-1472`, `PetitPotam`, `CVE-2021-1675`, `noPac`, `Rubeus`, `CrackMapExec`
  - Downloads: `kerbrute`, `linpeas.sh`, `winpeas.exe`, `PowerView.ps1`, `AdFind`, `PingCastle`, `tgpt`
- **Python Dependencies** (see `requirements.txt`):
  - `requests`
  - `bloodhound`
  - `ldapdomaindump`

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/jaberhasantaslim/AD-PTF.git
   cd AD-PTF
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Script to Install Tools**:
   ```bash
   sudo python3 ad-framework.py
   ```
   - Select option `1` (Tool Installation and Setup) to install required tools.
   - For anonymous mode, install and start Tor:
     ```bash
     sudo apt install tor
     sudo systemctl start tor
     ```
   - Configure `/etc/proxychains4.conf` to include:
     ```
     socks5 127.0.0.1 9050
     ```

4. **Verify Installation**:
   - Re-run option `1` to ensure all tools are installed correctly.
   - Check Tor status: `sudo systemctl status tor`.

## Usage

1. **Launch the Framework**:
   ```bash
   sudo python3 ad-framework.py
   ```

2. **Main Menu**:
   ```
   ╔═══════════════════════════════════════════════╗
   ║                   Main Menu                   ║
   ╠═══════════════════════════════════════════════╣
   ║ 1. Tool Installation and Setup               ║
   ║ 2. Start Penetration Testing                 ║
   ║ 3. Ask GPT for Help (tgpt)                   ║
   ║ 4. Exit                                      ║
   ╚═══════════════════════════════════════════════╝
   ```

3. **Options**:
   - **Option 1**: Installs and configures tools (e.g., `nmap`, `proxychains4`, `bloodhound`).
   - **Option 2**: Starts penetration testing with prompts for:
     - Target domain (e.g., `company.com`)
     - Target IP/range (e.g., `192.168.1.0/24`)
     - Domain Controller IP (optional)
     - Credentials (optional)
     - Wordlist path (default: `/usr/share/wordlists/rockyou.txt`)
     - Anonymous mode (Y/N)
     - Scan intensity (Aggressive Y/N)
   - **Option 3**: Queries `tgpt` for troubleshooting (e.g., `How to fix proxychains4 command not found`).
   - **Option 4**: Exits the framework.

4. **Example Execution**:
   ```bash
   ┌──(jaber㉿jaber)-[~/AD-PTF]
   └─$ sudo python3 ad-framework.py

   [ASCII Banner Here]

   ╔═══════════════════════════════════════════════╗
   ║                   Main Menu                   ║
   ╠═══════════════════════════════════════════════╣
   ║ 1. Tool Installation and Setup               ║
   ║ 2. Start Penetration Testing                 ║
   ║ 3. Ask GPT for Help (tgpt)                   ║
   ║ 4. Exit                                      ║
   ╚═══════════════════════════════════════════════╣
   
   Select option (1-4): 2

   [+] Penetration Testing Configuration
   ==================================================
   Enter target domain (e.g., company.com): company.com
   Enter target IP or IP range (e.g., 192.168.1.0/24): 10.201.127.223
   Enter Domain Controller IP (if known, else press Enter): 
   [+] Credentials (leave empty if unknown)
   Username: 
   Wordlist path [default: /usr/share/wordlists/rockyou.txt]: 
   Enable anonymous mode with proxychains4? (y/N): y
   Use Aggressive mode (fast, comprehensive)? (Y/N): y
   ```

5. **Output**:
   - Results are saved in `~/AD-PenTest-Results`.
   - Summary report: `penetration_test_report.txt`.
   - Zipped archive: `pentest_results_<timestamp>.zip`.
   - Individual result files are removed after zipping, keeping only the report and zip.

## Screenshots

![Main Menu](screenshots/main_menu.png)

*Main menu of AD-PTF running in a Kali Linux terminal.*

## Troubleshooting

- **Proxychains4 Errors**:
  - Install: `sudo apt install proxychains`.
  - Configure: Add `socks5 127.0.0.1 9050` to `/etc/proxychains4.conf`.
  - Verify Tor: `sudo systemctl status tor`.
- **LDAP Errors**:
  - Provide valid credentials or confirm the target supports anonymous binds.
  - Check connectivity: `ping <target_ip>`.
- **Tool Installation Issues**:
  - Re-run option `1` to install missing tools.
  - Install `wine32` for `PingCastle`: `sudo dpkg --add-architecture i386 && sudo apt update && sudo apt install wine32:i386`.
- **General Errors**:
  - Use option `3` (Ask GPT for Help) to query `tgpt` for specific issues (e.g., `How to fix nmap invalid argument error`).
  - Check logs in `~/AD-PenTest-Results` for details.

## Contributing

We welcome contributions to enhance AD-PTF! To contribute:
1. Fork the repository: https://github.com/jaberhasantaslim/AD-PTF
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m "Add your feature"`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a pull request with a clear description.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) and see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

- **Jaber Hasan**
- GitHub: [jaberhasantaslim](https://github.com/jaberhasantaslim)

## Acknowledgements

- Built with inspiration from tools like `BloodHound`, `Impacket`, and Kali Linux.
- Thanks to the open-source security community for providing robust AD attack tools.

---

⭐ **Star this repository** if you find it useful!  
📩 Open an issue for bugs, feature requests, or questions.  
🐦 Share on Twitter or LinkedIn to spread the word!