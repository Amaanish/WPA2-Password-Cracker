import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import subprocess
import os
import re
import threading

class WPA2GUI:
    def __init__(self, root):
        self.root = root
        root.title("PasswordCrackerBarrel")
        root.configure(bg="#121212")
        root.geometry("1000x520")

        self.cap_file = ""
        self.wordlist_file = ""
        self.attack_method = None
        self.extracted_data = {}

        title = tk.Label(root, text="PasswordCrackerBarrel", font=("Helvetica", 14, "bold"), fg="#00ffc8", bg="#121212")
        title.pack(pady=(5, 0))

        main_frame = tk.Frame(root, bg="#121212")
        main_frame.pack(fill=tk.BOTH, expand=True)

        control_frame = tk.Frame(main_frame, bg="#121212")
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        tk.Label(control_frame, text="Input Files", font=("Helvetica", 9, "bold"), fg="#00ffcc", bg="#121212").pack(anchor="w", pady=(0, 5))

        self.label = tk.Label(control_frame, text="Capture File (.cap):", fg="white", bg="#121212")
        self.label.pack(anchor="w")
        self.select_button = tk.Button(control_frame, text="Browse .cap File", width=22, command=self.browse_file)
        self.select_button.pack(pady=2)

        wordlist_frame = tk.Frame(control_frame, bg="#121212")
        wordlist_frame.pack(fill=tk.X, pady=5)
        self.wordlist_button = tk.Button(wordlist_frame, text="Wordlist: Not Loaded", width=22, command=self.load_wordlist, anchor="w")
        self.wordlist_button.pack(side=tk.LEFT)

        tk.Label(control_frame, text="Attack Methods", font=("Helvetica", 9, "bold"), fg="#00ffcc", bg="#121212").pack(pady=(10, 5))
        self.dict_button = tk.Button(control_frame, text="Dictionary Attack", width=22, command=lambda: self.set_attack_method(1))
        self.dict_button.pack(pady=1)
        self.hybrid_button = tk.Button(control_frame, text="Hybrid Attack", width=22, command=lambda: self.set_attack_method(2))
        self.hybrid_button.pack(pady=1)
        self.brute_button = tk.Button(control_frame, text="Brute Force", width=22, command=self.brute_force_warning)
        self.brute_button.pack(pady=1)

        tk.Label(control_frame, text="Actions", font=("Helvetica", 9, "bold"), fg="#00ffcc", bg="#121212").pack(pady=(10, 5))
        self.generate_wordlist_button = tk.Button(control_frame, text="Generate Wordlist", width=22, command=self.generate_wordlist)
        self.generate_wordlist_button.pack(pady=1)
        self.crack_button = tk.Button(control_frame, text="Start Cracking", width=22, state=tk.DISABLED, command=self.start_crack_thread)
        self.crack_button.pack(pady=1)
        self.exit_button = tk.Button(control_frame, text="Exit", width=22, command=self.root.quit)
        self.exit_button.pack(pady=1)

        self.output = scrolledtext.ScrolledText(main_frame, width=68, height=28, bg="#1e1e1e", fg="white", insertbackground="white")
        self.output.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
    def brute_force_warning(self):
        messagebox.showinfo(
            "Brute Force Disclaimer",
        "⚠ Brute force attacks are extremely slow and ineffective for passwords longer than 3 characters.\n\nIt is included for demonstration purposes only."
        )

    def browse_file(self):
        self.cap_file = filedialog.askopenfilename(filetypes=[("Capture files", "*.cap")])
        if self.cap_file:
            self.output.insert(tk.END, f"Selected: {self.cap_file}\n")
            self.output.see(tk.END)
            self.extract_handshake()

    def load_wordlist(self):
        file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file:
            self.wordlist_file = file
            filename = os.path.basename(file)
            display_name = filename if len(filename) <= 12 else filename[:9] + "..."
            self.wordlist_button.config(text=f"Wordlist: {display_name}")
            self.output.insert(tk.END, f"Wordlist loaded: {self.wordlist_file}\n")
        else:
            self.wordlist_file = ""
            self.wordlist_button.config(text="Wordlist: Not Loaded")
        self.output.see(tk.END)

    def set_attack_method(self, method):
        self.attack_method = method
        method_name = ["Dictionary", "Hybrid", "Brute Force"][method - 1]
        self.output.insert(tk.END, f"\n--- Attack Type: {method_name} ---\n")
        if method in [1, 2] and not self.wordlist_file:
            self.output.insert(tk.END, "[ERROR] Please load a wordlist first.\n")
        elif method == 3:
            warning_msg = "Brute force with passwords longer than 3 characters is extremely slow.\nContinue with max 3 characters?"
            if not messagebox.askyesno("Brute Force Warning", warning_msg):
                self.output.insert(tk.END, "[INFO] Brute force cancelled by user.\n")
                self.attack_method = None
                return
            self.output.insert(tk.END, "[INFO] Brute force max length set to 3.\n")
        self.output.see(tk.END)

    def extract_handshake(self):
        try:
            result = subprocess.run([
                "aircrack-ng", self.cap_file, "-J", "output"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            self.output.insert(tk.END, result.stdout + "\n")
            self.output.see(tk.END)
            text = result.stdout

            def extract_simple(tag):
                match = re.search(r"\[\*\] " + re.escape(tag) + r":\s+(.*)", text)
                return match.group(1).strip() if match else ""

            def extract_multiline_hex(tag):
                match = re.search(r"\[\*\] " + re.escape(tag) + r":\n((?:\s+[A-F0-9 ]+\n)+)", text)
                if match:
                    lines = match.group(1).strip().splitlines()
                    return " ".join(line.strip() for line in lines)
                return ""

            ssid_match = re.search(r"\[\*\] ESSID \(length: \d+\):\s+(.*)", text)
            ssid = ssid_match.group(1).strip() if ssid_match else ""

            self.extracted_data = {
                "ssid": ssid,
                "bssid": extract_simple("BSSID"),
                "sta": extract_simple("STA"),
                "anonce": extract_multiline_hex("anonce"),
                "snonce": extract_multiline_hex("snonce"),
                "mic": extract_simple("Key MIC"),
                "eapol": extract_multiline_hex("eapol"),
            }

            if not self.extracted_data['ssid'] or not self.extracted_data['bssid'] or not self.extracted_data['mic']:
                self.output.insert(tk.END, "[ERROR] Failed to extract one or more required fields.\n")
                self.output.see(tk.END)
                return

            self.output.insert(tk.END, "--- Extracted Data ---\n")
            for key, value in self.extracted_data.items():
                self.output.insert(tk.END, f"{key.upper()}: {value}\n\n")
            self.output.see(tk.END)

            self.crack_button.config(state=tk.NORMAL)

        except Exception as e:
            self.output.insert(tk.END, f"[ERROR] Failed to extract handshake: {str(e)}\n")
            self.output.see(tk.END)

    def format_eapol(self, raw):
        bytes_list = raw.strip().split()
        lines = [" ".join(bytes_list[i:i + 16]) for i in range(0, len(bytes_list), 16)]
        return "\n".join(lines)

    def start_crack_thread(self):
        thread = threading.Thread(target=self.run_crack_script)
        thread.daemon = True
        thread.start()

    def run_crack_script(self):
        if not self.attack_method:
            self.output.insert(tk.END, "Please select an attack method before starting.\n")
            self.output.see(tk.END)
            return
        if self.attack_method in [1, 2] and not self.wordlist_file:
            self.output.insert(tk.END, "[ERROR] Please load a wordlist file before proceeding with Dictionary/Hybrid attack.\n")
            self.output.see(tk.END)
            return

        self.output.insert(tk.END, "\nRunning cracking script...\n")
        self.output.see(tk.END)

        cmd = ["python3", "mycode.py"]
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        eapol_input = self.format_eapol(self.extracted_data['eapol']) + "\n\n"

        inputs = f"""{self.extracted_data['ssid']}
{self.extracted_data['bssid']}
{self.extracted_data['sta']}
{self.extracted_data['anonce']}
{self.extracted_data['snonce']}
{self.extracted_data['mic']}
{eapol_input}{self.attack_method}
"""

        if self.attack_method in [1, 2]:
            inputs += f"{self.wordlist_file}\n"
        elif self.attack_method == 3:
            inputs += "3\n"

        stdout, _ = process.communicate(input=inputs)
        self.output.insert(tk.END, stdout + "\n")
        self.output.see(tk.END)

        if self.attack_method == 3:
            if "Password not found." in stdout:
                self.output.insert(tk.END, "[WARNING] Brute-force was unsuccessful. Password may be longer than 3 characters.\n")
            elif "[+] Password found" not in stdout:
                self.output.insert(tk.END, "[INFO] No result returned. Please verify input.\n")
        self.output.see(tk.END)

    def generate_wordlist(self):
        popup = tk.Toplevel(self.root)
        popup.title("Generate Wordlist")
        popup.configure(bg="#1e1e1e")

        entries = []
        labels = ["Target Names", "Location", "Important Years", "Pets/Family Names", "Favorite Things"]

        for label in labels:
            row = tk.Frame(popup, bg="#1e1e1e")
            row.pack(padx=10, pady=5, fill=tk.X)
            tk.Label(row, text=label+":", width=20, anchor='w', bg="#1e1e1e", fg="white").pack(side=tk.LEFT)
            entry = tk.Entry(row, width=40)
            entry.pack(side=tk.RIGHT, expand=True, fill=tk.X)
            entries.append(entry)

        def save():
            words = []
            for entry in entries:
                raw = entry.get().strip()
                if raw:
                    items = [item.strip() for item in raw.split(",") if item.strip()]
                    for word in items:
                        words.extend([word, word + "123", word[::-1], word.upper(), word.lower()])
            save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if save_path:
                with open(save_path, "w") as f:
                    for word in sorted(set(words)):
                        f.write(word + "\n")
                self.output.insert(tk.END, f"Wordlist saved to: {save_path}\n")
                self.output.see(tk.END)
            popup.destroy()

        tk.Button(popup, text="Generate", command=save, width=20).pack(pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = WPA2GUI(root)
    root.mainloop()
