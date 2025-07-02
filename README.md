# WPA2 Wi-Fi Password Cracker

A comprehensive WPA2 handshake cracking tool designed for educational purposes and authorized penetration testing. This tool combines a powerful backend engine with an intuitive GUI interface, supporting multiple attack methods to audit wireless network security through captured `.cap` files.

**Created for CSCI369 Project in collaboration with Yaasir Bin Muneer**

> ⚠️ **DISCLAIMER**: This tool is for **educational and authorized penetration testing purposes only**. Unauthorized use against networks you don't own or have explicit permission to test is illegal and unethical. Always ensure you have proper authorization before testing any network.

---

##  Features

-  Automatic Handshake Extraction**: Seamlessly extract WPA2 handshake data from `.cap` files using `aircrack-ng`
-  Multiple Attack Methods**:
  -  Dictionary Attack**: Test passwords from wordlists
  -  Hybrid Attack**: Enhance dictionary entries with common patterns and modifications
  -  Brute Force Attack**: Systematically test all character combinations (optimized for short passwords)
-  User-Friendly GUI**: Built with `tkinter` for intuitive operation
-  Smart Wordlist Generator**: Create personalized dictionaries based on target information
-  Multithreaded Interface**: Non-blocking execution for smooth user experience
-  Real-time Progress Tracking**: Monitor cracking progress with detailed output

---

## 📋 Requirements

### System Requirements
- **Operating System**: Kali Linux (recommended) or other Linux distributions
- **Python Version**: Python 3.10 or higher
- **Network Tools**: aircrack-ng suite

### Python Dependencies
```bash
pip install cryptography
```

### System Dependencies (Kali Linux)
```bash
sudo apt update
sudo apt install aircrack-ng wireshark
```

---

## 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Amaanish/WPA2-Password-Cracker.git
   cd WPA2-Password-Cracker
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   # or manually install:
   pip install cryptography
   ```

3. **Verify system dependencies**:
   ```bash
   aircrack-ng --help
   ```

---

##  Usage

### GUI Interface
1. **Launch the application**:
   ```bash
   python3 mycodeGUI.py
   ```

2. **Load capture file**: Click "Browse .cap File" and select your WPA2 handshake capture

3. **Choose attack method**:
   - For **Dictionary/Hybrid**: Load a wordlist file first
   - For **Brute Force**: Confirm the maximum password length (recommended: ≤3 characters)

4. **Start cracking**: Click "Start Cracking" and monitor progress in real-time

### Command Line Interface
```bash
python3 mycode.py
```
Then provide the required inputs interactively:
- SSID, BSSID, STA MAC addresses
- Anonce, Snonce values
- MIC and EAPOL data
- Attack method and parameters

---

##  Project Structure

```
WPA2-Password-Cracker/
├── mycode.py           # Core cracking engine
├── mycodeGUI.py        # GUI interface
├── README.md           # Project documentation
├── requirements.txt    # Python dependencies
```

---

##  Attack Methods Explained

### 🔤 Dictionary Attack
- Tests passwords from a predefined wordlist
- **Best for**: Common passwords, leaked password databases
- **Speed**: Fast (depends on wordlist size)

### 🔀 Hybrid Attack  
- Enhances dictionary words with common modifications:
  - Appends numbers (123, 1234, 2023)
  - Adds special characters (!, @, 007)
  - Capitalizes first letter
  - Reverses words
- **Best for**: Passwords with predictable patterns
- **Speed**: Moderate (3-9x dictionary size)

### 🔢 Brute Force Attack
- Tests all possible character combinations
- **Character set**: `a-z`, `A-Z`, `0-9`, `!@#$%^&*()`
- **Best for**: Very short passwords (≤4 characters)
- **Speed**: Extremely slow for longer passwords

---

##  Performance Notes

| Password Length | Brute Force Combinations | Estimated Time* |
|----------------|---------------------------|-----------------|
| 3 characters   | ~300K                    | Minutes         |
| 4 characters   | ~22M                     | Hours           |
| 5 characters   | ~1.6B                    | Days            |
| 8+ characters  | Astronomical             | Impractical     |

*Times are estimates and vary based on hardware

---

##  Ethical Usage Guidelines

-  **Authorized Testing**: Only test networks you own or have explicit written permission to test
-  **Educational Purpose**: Use for learning cybersecurity concepts and defensive strategies  
-  **Responsible Disclosure**: Report vulnerabilities through proper channels
-  **Unauthorized Access**: Never attempt to crack networks without permission
-  **Malicious Intent**: Don't use for illegal activities or privacy violations

---

##  Troubleshooting

### Common Issues

**"Command not found: aircrack-ng"**
```bash
sudo apt install aircrack-ng
```

**"No handshake found in capture file"**
- Ensure the capture contains a complete 4-way WPA2 handshake
- Try different capture files or recapture the handshake

**"Permission denied" errors**
```bash
sudo python3 mycodeGUI.py
```

**GUI not displaying properly**
- Ensure you're running in a graphical environment
- Try updating tkinter: `sudo apt install python3-tk`

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Yaasir Bin Muneer** - Project collaborator
- **CSCI369 Course at UOWD** - Academic context
- **aircrack-ng team** - For the excellent wireless security tools
- **Python cryptography library** - For robust cryptographic implementations

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally! 🛡️
