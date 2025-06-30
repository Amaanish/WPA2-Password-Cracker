import hmac
import hashlib
import sys
from binascii import unhexlify
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend
from itertools import product

dict_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"

def get_PMK(passphrase, ssid):
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)

def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) // 160):
        hmacsha1 = hmac.new(key, A + b'\x00' + B + bytes([i]), hashlib.sha1)
        R += hmacsha1.digest()
        i += 1
    return R[:blen]

def get_PTK(pmk, aa, spa, anonce, snonce):
    A = b"Pairwise key expansion"
    B = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    return customPRF512(pmk, A, B)

def calc_mic(ptk, eapol, key_desc_ver):
    if key_desc_ver == 1:
        mic = hmac.new(ptk[0:16], eapol, hashlib.md5).digest()
    elif key_desc_ver == 2:
        mic = hmac.new(ptk[0:16], eapol, hashlib.sha1).digest()[:16]
    elif key_desc_ver == 3:
        c = CMAC(algorithms.AES(ptk[0:16]), backend=default_backend())
        c.update(eapol)
        mic = c.finalize()
    else:
        raise Exception("Unsupported key descriptor version")
    return mic

def dict_generator(wordlist):
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line.strip()

def hybrid_generator(wordlist):
    suffixes = ["", "123", "1234", "2023", "!", "@", "007", "99", "00"]
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            for suffix in suffixes:
                yield word + suffix
                yield word.capitalize() + suffix
                yield word[::-1] + suffix

def brute_generator(max_len=4):
    for length in range(1, max_len + 1):
        for combo in product(dict_chars, repeat=length):
            yield "".join(combo)

def try_cracking(ssid, bssid, sta, anonce, snonce, eapol_hex, mic_hex, version, guess_generator):
    bssid_bytes = unhexlify(bssid.replace(":", ""))
    sta_bytes = unhexlify(sta.replace(":", ""))
    anonce_bytes = unhexlify(anonce.replace(" ", ""))
    snonce_bytes = unhexlify(snonce.replace(" ", ""))
    eapol = unhexlify(eapol_hex.replace(" ", "").replace("\n", ""))
    mic = unhexlify(mic_hex.replace(" ", ""))

    for i, guess in enumerate(guess_generator, 1):
        pmk = get_PMK(guess, ssid)
        ptk = get_PTK(pmk, bssid_bytes, sta_bytes, anonce_bytes, snonce_bytes)
        calc = calc_mic(ptk, eapol, version)
        if calc[:16] == mic:
            print(f"[+] Password found: {guess}")
            print(f"[+] Total guesses: {i}")
            return
        if i % 1000 == 0:
            print(f"[-] Tried {i} guesses...")
    print("[-] Password not found.")

if __name__ == "__main__":
    readline = sys.stdin.readline

    ssid = readline().strip()
    bssid = readline().strip()
    sta = readline().strip()
    anonce = readline().strip()
    snonce = readline().strip()
    mic = readline().strip()

    # Read EAPOL until blank line
    eapol_lines = []
    while True:
        line = readline()
        if not line.strip():
            break
        eapol_lines.append(line.strip())
    eapol = " ".join(eapol_lines)

    method = readline().strip()
    version = 2

    if method == "1":
        wordlist_path = readline().strip()
        gen = dict_generator(wordlist_path)
    elif method == "2":
        wordlist_path = readline().strip()
        gen = hybrid_generator(wordlist_path)
    elif method == "3":
        max_len = int(readline().strip())
        gen = brute_generator(max_len)
    else:
        print("Invalid method.")
        sys.exit(1)

    try_cracking(ssid, bssid, sta, anonce, snonce, eapol, mic, version, gen)
