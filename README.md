WPA2 Wi-Fi Password Cracker

This is a WPA2 handshake cracking tool that supports **dictionary**, **hybrid**, and **brute-force** attacks. It combines a powerful backend engine with a user-friendly GUI, allowing users to audit wireless network security through captured `.cap` files.
This was created for CSCI369 Project in collaboration with Yaasir Bin Muneer.

> This tool is for **educational and authorized penetration testing purposes only**. Unauthorized use against networks you don’t own or have explicit permission to test is illegal and unethical.

---

##  Features

-  Extract WPA2 handshake data automatically from `.cap` files using `aircrack-ng`.
-  Attack methods:
  - **Dictionary Attack** — test known passwords.
  - **Hybrid Attack** — modify dictionary entries with common patterns.
  - **Brute Force** — test all combinations of characters (short passwords only).
- GUI-based interface built with `tkinter` for ease of use.
- ✍Wordlist generator to craft personalized dictionaries.
-  Multithreaded interface for non-blocking execution.

---

##  Requirements

### Python Dependencies (use 3.10)
### Kali Linux
### Wireshark

Install with:

```bash
pip install cryptography
```

and clone:
``` bash
git clone https://github.com/Amaanish/WPA2-Password-Cracker.git
```
