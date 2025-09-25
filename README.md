AD-PTF: Active Directory Penetration Testing Framework

   ___    ____        _____            _____     _____    _____    _____ 
  / _ \  |  _ \      |  ___|   ___    |  ___|   /  _  \  |  ___|  /  _  \
 / /_\ \ | | | |____ | |__    / _ \   | |__    | | | |  | |__    | | | |
/ _____ \| | | |____||  __|  | | | |  |  __|   | | | |  |  __|   | | | |
/ /   \ \| |_/ /     | |___  | |_| |  | |___   | |_| |  | |___   | |_| |
\/     \/|____/      |_____|  \___/   |_____|   \_____/  |_____|  \_____/
                                                                        
Active Directory Penetration Testing Framework v2.0
Author: Jaber Hasan

Overview
AD-PTF (Active Directory Penetration Testing Framework) is a Python-based tool designed to automate the installation and execution of Active Directory attack tools for authorized penetration testing. It streamlines network discovery, AD enumeration, vulnerability assessment, password attacks, exploitation, and post-exploitation, generating minimal attack reports for analysis.

⚠️ WARNING: This tool is for authorized penetration testing only. Ensure you have explicit permission from the target system's owner before use. Unauthorized use may violate laws and ethical guidelines.

Features

Tool Installation: Automates setup of AD attack tools like nmap, masscan, bloodhound, ldapsearch, and more.
Network Discovery: Scans target networks with customizable port and intensity settings.
AD Enumeration: Identifies AD objects, users, and configurations using tools like smbclient and ldapdomaindump.
Vulnerability Assessment: Detects common AD vulnerabilities (e.g., SMBGhost, EternalBlue, Zerologon).
Password Attacks: Supports password spraying and cracking with hydra, kerbrute, and hashcat.
Exploitation: Executes exploits like PetitPotam, PrintNightmare, and Golden Ticket attacks.
Post-Exploitation: Facilitates privilege escalation and lateral movement with BloodHound, PowerView, and PlumHound.
Anonymous Mode: Supports proxychains4 for anonymized testing via Tor or other proxies.
Interactive Interface: User-friendly menu for setup, testing, and troubleshooting.
Report Generation: Outputs results to ~/AD-PenTest-Results with a zipped archive and a summary report.

Requirements

Operating System: Linux (tested on Kali Linux)
Python: 3.0 or higher
Dependencies:
Binaries: masscan, nmap, ldapsearch, smbclient, rpcclient, hydra, proxychains, hashcat, go, ruby, wine, wine32
Python packages: requests, bloodhound, ldapdomaindump
Git repositories: impacket, PlumHound, Responder, windapsearch, CVE-2020-1472, PetitPotam, CVE-2021-1675, noPac, Rubeus, CrackMapExec
Downloads: kerbrute, linpeas.sh, winpeas.exe, PowerView.ps1, AdFind, PingCastle, tgpt



See requirements.txt for Python dependencies.
Installation

Clone the Repository:
git clone https://github.com/jaberhasantaslim/AD-PTF.git
cd AD-PTF


Install Python Dependencies:
pip install -r requirements.txt


Run the Script to Install Tools:
sudo python3 ad-framework.py


Select option 1 (Tool Installation and Setup) to install required tools.
If using anonymous mode, install and start Tor:sudo apt install tor
sudo systemctl start tor


Configure /etc/proxychains4.conf with a proxy (e.g., socks5 127.0.0.1 9050).


Verify Setup:

Re-run option 1 to ensure all tools are installed correctly.



Usage

Run the Script:
sudo python3 ad-framework.py


Navigate the Main Menu:
╔═══════════════════════════════════════════════╗
║                   Main Menu                   ║
╠═══════════════════════════════════════════════╣
║ 1. Tool Installation and Setup               ║
║ 2. Start Penetration Testing                 ║
║ 3. Ask GPT for Help (tgpt)                   ║
║ 4. Exit                                      ║
╚═══════════════════════════════════════════════╝


Option 1: Installs and configures tools (e.g., nmap, proxychains4).
Option 2: Starts the penetration testing workflow with prompts for:
Target domain (e.g., company.com)
Target IP/range (e.g., 192.168.1.0/24)
Domain Controller IP (optional)
Credentials (optional)
Wordlist path (default: /usr/share/wordlists/rockyou.txt)
Anonymous mode (Y/N)
Scan intensity (Aggressive Y/N)


Option 3: Queries tgpt for troubleshooting (e.g., How to fix proxychains4 command not found).
Option 4: Exits the framework.


Example Run:
┌──(jaber㉿jaber)-[~/mygithub/My_AD_Tools_Project]
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


Output:

Results are saved in ~/AD-PenTest-Results.
Summary report: penetration_test_report.txt.
Zipped archive: pentest_results_<timestamp>.zip.



Screenshots

Troubleshooting

Proxychains4 Errors:
Install: sudo apt install proxychains.
Configure: Add socks5 127.0.0.1 9050 to /etc/proxychains4.conf.
Verify Tor: sudo systemctl status tor.


LDAP Errors:
Provide credentials or confirm anonymous binds are supported.


Tool Failures:
Re-run option 1 to install missing tools.
Use option 3 to query tgpt for specific errors.


Wine32 for PingCastle:
Install: sudo dpkg --add-architecture i386 && sudo apt update && sudo apt install wine32:i386.



Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a feature branch: git checkout -b feature/your-feature.
Commit changes: git commit -m "Add your feature".
Push to the branch: git push origin feature/your-feature.
Open a pull request.

See CONTRIBUTING.md for details.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Author

Jaber Hasan
GitHub: jaberhasantaslim

Acknowledgements

Inspired by tools like BloodHound, Impacket, and Kali Linux.
Thanks to the open-source community for providing robust AD attack tools.


⭐ Star this repository if you find it useful!📩 Open an issue for bugs or feature requests.
