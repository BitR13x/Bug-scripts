# CTF-Recon v1.0 - HackTheBox & TryHackMe Specialized Tool

A lightweight, fast, and CTF-optimized reconnaissance tool specifically designed for HackTheBox and TryHackMe environments. Built for speed, stealth, and CTF-specific enumeration patterns.

## 🎯 Why CTF-Recon?

Traditional recon tools are designed for real-world penetration testing, but CTF environments have different characteristics:

- **Single Target Focus**: CTFs typically involve one target machine
- **Time Constraints**: Speed is crucial in competitive environments
- **Known Patterns**: CTF boxes often follow predictable patterns
- **Flag Hunting**: Specific focus on finding flags and proof files
- **Platform-Specific**: HTB and THM have different methodologies

## 🚀 Key Features

### CTF-Optimized Scanning
- **Platform Detection**: Automatically detects HackTheBox vs TryHackMe
- **Smart Port Selection**: Focuses on commonly used CTF ports
- **Fast Enumeration**: Optimized for speed without sacrificing thoroughness
- **Flag Detection**: Automatically searches for flags in responses

### Service Enumeration
- **Automated Service Testing**: Tests default credentials automatically
- **CTF-Specific Wordlists**: Uses wordlists optimized for CTF environments
- **Quick Web Enumeration**: Fast directory and file discovery
- **Service-Specific Scripts**: Tailored enumeration for each service

### Exploit Integration
- **Metasploit Commands**: Auto-generates MSF resource scripts
- **Searchsploit Integration**: Finds relevant exploits automatically
- **CVE Mapping**: Maps services to known vulnerabilities
- **Default Credential Testing**: Tests common CTF credentials

### Reporting
- **CTF-Style Reports**: Clean, focused reports for CTF documentation
- **Interactive HTML**: Modern web interface with collapsible sections
- **Markdown Notes**: Perfect for CTF writeups
- **Quick Reference**: Fast access to key findings and commands

## 📋 Prerequisites

### Required Tools
```bash
# Core tools (usually pre-installed on Kali)
sudo apt update
sudo apt install nmap gobuster nikto whatweb smbclient enum4linux

# Optional but recommended
sudo apt install searchsploit metasploit-framework sshpass mysql-client

# Wordlists
sudo apt install seclists dirb wordlists
```

### Tool Verification
```bash
# Check if tools are available
./ctf-recon.sh --help
```

## 🎮 Quick Start

### Basic Usage
```bash
# Quick scan (recommended for most CTFs)
./ctf-recon.sh -t 10.10.10.100

# Full comprehensive scan
./ctf-recon.sh -t 10.10.10.100 -a

# Interactive mode (guided setup)
./ctf-recon.sh
```

### Common CTF Scenarios

#### HackTheBox Machine
```bash
# Standard HTB approach
./ctf-recon.sh -t 10.10.10.100 -a --platform htb

# Quick enumeration for easy boxes
./ctf-recon.sh -t 10.10.10.100 -q -e
```

#### TryHackMe Room
```bash
# THM room with web focus
./ctf-recon.sh -t 10.10.10.100 -w -e --platform thm

# Quick start for THM
./ctf-recon.sh --quick-start 10.10.10.100
```

#### Custom Port Range
```bash
# Specific ports only
./ctf-recon.sh -t 10.10.10.100 -p 80,443,8080,9999

# Web application focus
./ctf-recon.sh -t 10.10.10.100 -p 80,443 -w
```

## 🛠️ Command Reference

### Scan Types
| Option | Description | Use Case |
|--------|-------------|----------|
| `-q, --quick` | Common ports only | Fast initial recon |
| `-f, --full` | All 65535 ports | Thorough enumeration |
| `-a, --all` | Complete scan suite | Comprehensive analysis |
| `-p, --ports` | Custom port range | Targeted scanning |

### Modes
| Option | Description | When to Use |
|--------|-------------|-------------|
| `-A, --aggressive` | Fast, high threads | Time-constrained CTFs |
| `-s, --stealth` | Slow, low profile | Stealth challenges |
| `-e, --exploits` | Enable exploit search | Vulnerability assessment |
| `-w, --web` | Web application focus | Web-heavy challenges |

### Examples by Difficulty

#### Easy/Beginner Boxes
```bash
# Quick and simple
./ctf-recon.sh -t TARGET -q -e

# Focus on common services
./ctf-recon.sh -t TARGET -p 21,22,80,139,445
```

#### Medium Boxes
```bash
# Comprehensive scan
./ctf-recon.sh -t TARGET -a

# Aggressive enumeration
./ctf-recon.sh -t TARGET -A -e -w
```

#### Hard/Insane Boxes
```bash
# Full port range with all features
./ctf-recon.sh -t TARGET -f -A -e -w

# Custom timeout for slow responses
./ctf-recon.sh -t TARGET -a --timeout 60
```

## 📊 Output Structure

```
ctf-scans/
└── 10.10.10.100_20250702_210000/
    ├── ctf_report.html          # Main interactive report
    ├── ctf_notes.md             # Markdown notes for writeups
    ├── summary.txt              # Quick text summary
    ├── findings.txt             # Key discoveries
    ├── ctf-recon.log           # Detailed execution log
    ├── nmap/                    # Port scan results
    │   ├── quick_scan.txt
    │   ├── service_scan.txt
    │   └── *.xml
    ├── services/                # Service enumeration
    │   ├── ftp_anonymous.txt
    │   ├── smb_shares.txt
    │   └── enum4linux.txt
    ├── web/                     # Web enumeration
    │   ├── gobuster_80.txt
    │   ├── nikto_80.txt
    │   └── whatweb_80.txt
    └── exploits/                # Exploitation resources
        ├── metasploit_*.rc
        ├── searchsploit_*.txt
        └── default_creds_*.txt
```

## 🎯 CTF-Specific Features

### Platform Detection
The tool automatically detects the CTF platform based on IP ranges:

- **HackTheBox**: `10.10.10.x`, `10.10.11.x`, `10.129.x.x`
- **TryHackMe**: `10.10.x.x`

### Flag Detection
Automatically searches for common flag formats:
- `flag{...}`
- `HTB{...}`
- `THM{...}`
- `CTF{...}`

### Common CTF Paths
Checks for typical CTF files:
- `/flag.txt`, `/user.txt`, `/root.txt`
- `/proof.txt`, `/flag`
- Configuration files and backups

### Default Credentials
Tests common CTF credentials:
- `admin:admin`
- `root:root`
- `guest:guest`
- Service-specific defaults

## 🔧 Configuration

### Custom Wordlists
Edit `config.sh` to use your preferred wordlists:
```bash
export CTF_DIRS="/path/to/your/wordlist.txt"
export CTF_FILES="/path/to/files.txt"
```

### Performance Tuning
```bash
# Fast scanning
export NMAP_THREADS=200
export GOBUSTER_THREADS=100

# Stealth mode
export NMAP_THREADS=10
export GOBUSTER_THREADS=10
```

### Platform-Specific Settings
```bash
# HackTheBox optimizations
export TIMEOUT=60
export AGGRESSIVE_MODE=true

# TryHackMe optimizations
export TIMEOUT=30
export STEALTH_MODE=false
```

## 📝 Report Features

### Interactive HTML Report
- **Dark Theme**: Easy on the eyes during long sessions
- **Collapsible Sections**: Organized information display
- **Copy-to-Clipboard**: Quick command copying
- **Platform Badges**: Visual platform identification
- **Finding Categories**: Color-coded severity levels

### Markdown Notes
Perfect for CTF writeups:
- Structured format
- Code blocks for commands
- Checklist for manual testing
- Easy to convert to other formats

### Metasploit Integration
Auto-generated resource scripts:
```bash
# Use generated MSF commands
cd scan_directory/exploits/
msfconsole -r metasploit_http_80.rc
```

## 🚀 Advanced Usage

### Chaining with Other Tools
```bash
# Export results for other tools
./ctf-recon.sh -t TARGET -q
cat ctf-scans/*/nmap/quick_scan.txt | grep open | cut -d'/' -f1 > open_ports.txt

# Use with custom scripts
./ctf-recon.sh -t TARGET -a
python3 custom_exploit.py --target TARGET --ports $(cat open_ports.txt)
```

### Integration with CTF Workflows
```bash
# Quick recon for time-limited CTFs
./ctf-recon.sh -t TARGET -A -e

# Detailed analysis for learning
./ctf-recon.sh -t TARGET -f -v

# Web-focused enumeration
./ctf-recon.sh -t TARGET -w --timeout 60
```

### Automation Scripts
```bash
#!/bin/bash
# Auto-recon for multiple targets
for target in $(cat targets.txt); do
    ./ctf-recon.sh -t $target -a
done
```

## 🐛 Troubleshooting

### Common Issues

1. **Target Not Responding**
   ```bash
   # Check connectivity
   ping -c 4 TARGET
   
   # Force scan anyway
   ./ctf-recon.sh -t TARGET --force
   ```

2. **Missing Tools**
   ```bash
   # Install missing dependencies
   sudo apt install nmap gobuster nikto
   ```

3. **Slow Scanning**
   ```bash
   # Use aggressive mode
   ./ctf-recon.sh -t TARGET -A
   
   # Reduce timeout
   ./ctf-recon.sh -t TARGET --timeout 15
   ```

4. **No Results**
   ```bash
   # Check with verbose mode
   ./ctf-recon.sh -t TARGET -v
   
   # Try full port scan
   ./ctf-recon.sh -t TARGET -f
   ```

### Debug Mode
```bash
# Enable verbose logging
./ctf-recon.sh -t TARGET -v

# Check log file
tail -f ctf-scans/*/ctf-recon.log
```

## 🎓 CTF Methodology

### Recommended Workflow

1. **Initial Recon**
   ```bash
   ./ctf-recon.sh -t TARGET -q
   ```

2. **Review Results**
   - Open HTML report
   - Check for obvious vulnerabilities
   - Note interesting services

3. **Deep Enumeration**
   ```bash
   ./ctf-recon.sh -t TARGET -a
   ```

4. **Manual Testing**
   - Test default credentials
   - Explore web applications
   - Check for misconfigurations

5. **Exploitation**
   - Use generated Metasploit commands
   - Try suggested exploits
   - Perform privilege escalation

### Time Management
- **5 minutes**: Quick scan and initial assessment
- **15 minutes**: Full enumeration and service testing
- **30 minutes**: Exploit research and manual testing
- **60 minutes**: Deep analysis and custom exploitation

## 🏆 CTF Tips

### HackTheBox Specific
- Always check for web applications on non-standard ports
- Look for version information in service banners
- Check for default credentials on admin panels
- Enumerate SMB shares thoroughly

### TryHackMe Specific
- Follow the room's hints and questions
- Check for obvious misconfigurations first
- Look for educational vulnerabilities
- Document your methodology for learning

### General CTF Tips
- Start with the most obvious attack vectors
- Always check for default credentials
- Look for version-specific exploits
- Don't forget about privilege escalation
- Document everything for writeups

## 📚 Learning Resources

### Recommended Reading
- [HackTheBox Academy](https://academy.hackthebox.com/)
- [TryHackMe Learning Paths](https://tryhackme.com/paths)
- [OSCP Methodology](https://github.com/0x4D31/awesome-oscp)

### Practice Platforms
- [HackTheBox](https://hackthebox.com/) - Advanced CTF challenges
- [TryHackMe](https://tryhackme.com/) - Beginner-friendly rooms
- [VulnHub](https://vulnhub.com/) - Downloadable VMs

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional service enumeration modules
- More CTF-specific wordlists
- Platform-specific optimizations
- New exploit detection methods

## 📄 License

This tool is for educational purposes and authorized testing only. Always ensure you have permission before scanning any targets.

## 🙏 Acknowledgments

- HackTheBox and TryHackMe communities
- Tool developers (nmap, gobuster, nikto, etc.)
- CTF community for methodologies and techniques

---

**Happy Hacking! 🎉**

*Remember: The goal is to learn and improve your skills. Take time to understand each step of the process, not just run automated tools.*
