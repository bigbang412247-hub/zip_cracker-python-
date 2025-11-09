#!/usr/bin/env python3
"""
zip_cracker_tool.py

Robust ZIP password recovery GUI (for files you own / have permission to test).

Features:
- Tkinter GUI (dark theme)
- Select ZIP + select wordlist (.txt) or load default Kali rockyou
- Reads wordlist robustly (utf-8, latin-1 fallback)
- Tests passwords using (in order): `unzip -P <pw> -t`, Python zipfile attempts, `7z t -p<pw>`
- Detects AES/strong encryption and optionally attempt zip2john+john if available
- Threaded worker -> UI via queue (no direct widget updates from worker)
- Stops immediately when a password is found; shows a single popup with Copy + Extract options
- Minimal console noise and throttled UI updates
- Use responsibly: only on archives you own / have permission to access

Save as zip_cracker_tool.py and run: python3 zip_cracker_tool.py
"""

import os
import sys
import time
import queue
import threading
import subprocess
import shutil
import zipfile
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

# -------- Configuration --------
ZIP_CMD = "unzip"                 # system unzip
SEVENZ_CMD = "7z"                 # p7zip-full (optional)
ZIP2JOHN_CMD = "zip2john"         # optional for john fallback
JOHN_CMD = "john"                 # optional
DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

# -------- Helper subprocess runner --------
def run_quiet(cmd, timeout=8):
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        return proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return 1, "timeout"
    except Exception as e:
        return -1, str(e)

# -------- Password test methods --------
def test_with_unzip(zipfile_path, password, timeout=6):
    """Test using system unzip - returns (True/False, output)."""
    if not shutil.which(ZIP_CMD):
        return False, "unzip not available"
    rc, out = run_quiet([ZIP_CMD, "-o", "-P", password, "-t", zipfile_path], timeout=timeout)
    return (rc == 0), out

def test_with_7z(zipfile_path, password, timeout=8):
    """Test with 7z (if available)."""
    if not shutil.which(SEVENZ_CMD):
        return False, "7z not available"
    rc, out = run_quiet([SEVENZ_CMD, "t", "-p" + password, zipfile_path], timeout=timeout)
    return (rc == 0), out

def test_with_zipfile(zipfile_path, password):
    """Try opening first file in archive using python zipfile with multiple encodings."""
    try:
        with zipfile.ZipFile(zipfile_path) as zf:
            names = zf.namelist()
            if not names:
                return False, "empty archive"
            name = names[0]
            for enc in ("utf-8", "latin-1", "cp437"):
                try:
                    pwd_bytes = password.encode(enc, errors="replace")
                except Exception:
                    continue
                try:
                    with zf.open(name, "r", pwd=pwd_bytes) as f:
                        f.read(1)
                    return True, f"zipfile success encoding={enc}"
                except RuntimeError:
                    # wrong password raises RuntimeError on many zips
                    pass
                except Exception:
                    pass
        return False, "zipfile tests failed"
    except Exception as e:
        return False, f"zipfile error: {e}"

def detect_aes(zipfile_path):
    """Try to detect AES/strong encryption hints using zipinfo/unzip -Z outputs."""
    try:
        if shutil.which("zipinfo"):
            rc, out = run_quiet(["zipinfo", "-v", zipfile_path], timeout=4)
            text = out.lower()
        else:
            rc, out = run_quiet([ZIP_CMD, "-Z", "-v", zipfile_path], timeout=4)
            text = out.lower()
        for token in ("aes", "strong encryption", "winzip"):
            if token in text:
                return True
        return False
    except Exception:
        return False

def try_john_fallback(zipfile_path, wordlist_path, enqueue):
    """If zip2john/john exist, attempt to run john with provided wordlist. Return found password or None."""
    if not (shutil.which(ZIP2JOHN_CMD) and shutil.which(JOHN_CMD)):
        enqueue(("log", "zip2john/john not available; skipping john fallback"))
        return None
    enqueue(("log", "Running zip2john (producing hash)..."))
    try:
        proc = subprocess.run([ZIP2JOHN_CMD, zipfile_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        hash_out = proc.stdout
        if not hash_out.strip():
            enqueue(("log", "zip2john produced no hash"))
            return None
        tmp = tempfile.NamedTemporaryFile(mode="w", delete=False)
        tmp.write(hash_out)
        tmp.flush()
        tmp.close()
        hashfile = tmp.name
        enqueue(("log", f"Running john with wordlist: {wordlist_path}"))
        john_proc = subprocess.run([JOHN_CMD, "--wordlist=" + wordlist_path, hashfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        show_proc = subprocess.run([JOHN_CMD, "--show", hashfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out = show_proc.stdout or ""
        # parse john --show output for password (heuristic)
        for line in out.splitlines():
            # typical john --show lines: user:password
            if ":" in line:
                parts = line.split(":")
                if parts and parts[-1].strip():
                    candidate = parts[-1].strip()
                    try:
                        os.unlink(hashfile)
                    except Exception:
                        pass
                    enqueue(("log", f"john reported password: {candidate}"))
                    return candidate
        try:
            os.unlink(hashfile)
        except Exception:
            pass
        enqueue(("log", "john did not find a password"))
    except Exception as e:
        enqueue(("log", f"zip2john/john error: {e}"))
    return None

# -------- GUI App --------
class ZipCrackerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ZIP Cracker — Tool")
        self.geometry("820x600")
        self.minsize(760, 520)
        self.configure(bg="#0f1724")

        # state
        self.zip_path = tk.StringVar()
        self.wordlist_path = tk.StringVar(value=DEFAULT_WORDLIST if os.path.exists(DEFAULT_WORDLIST) else "(none)")
        self._queue = queue.Queue()
        self._worker = None
        self._stop_event = threading.Event()
        self._found = False
        self._found_details = None  # (password, method, idx)

        self._build_ui()
        self.after(120, self._process_queue)

    def _build_ui(self):
        pad = dict(padx=12, pady=8)
        # Header
        header = tk.Frame(self, bg="#0f1724")
        header.pack(fill="x", **pad)
        tk.Label(header, text="ZIP Cracker — Tool", font=("Inter", 18, "bold"), fg="#e6eef6", bg="#0f1724").pack(anchor="w")
        tk.Label(header, text="Use only on files you own or have explicit permission to test.", fg="#b7c7dd", bg="#0f1724").pack(anchor="w")

        # Selection frame
        sel = tk.Frame(self, bg="#0f1724")
        sel.pack(fill="x", padx=12, pady=(4,6))

        tk.Label(sel, text="ZIP file:", fg="#dbeafe", bg="#0f1724").grid(row=0, column=0, sticky="w")
        ttk.Entry(sel, textvariable=self.zip_path, width=72).grid(row=1, column=0, sticky="w")
        ttk.Button(sel, text="Browse ZIP", command=self._browse_zip).grid(row=1, column=1, padx=6)

        tk.Label(sel, text="Wordlist (.txt):", fg="#dbeafe", bg="#0f1724").grid(row=2, column=0, sticky="w", pady=(8,0))
        ttk.Label(sel, textvariable=self.wordlist_path, foreground="#9fe0a6", background="#0f1724").grid(row=3, column=0, sticky="w")
        ttk.Button(sel, text="Select Wordlist", command=self._browse_wordlist).grid(row=3, column=1, padx=6)
        ttk.Button(sel, text="Load default (rockyou)", command=self._load_default).grid(row=3, column=2, padx=6)

        # Controls
        ctrl = tk.Frame(self, bg="#0f1724")
        ctrl.pack(fill="x", padx=12, pady=(6,0))
        self.start_btn = ttk.Button(ctrl, text="Start", command=self.start, width=14)
        self.start_btn.pack(side="left", padx=(0,8))
        self.stop_btn = ttk.Button(ctrl, text="Stop", command=self.stop, width=14, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(ctrl, text="Clear Console", command=self._clear_console, width=14).pack(side="right")

        # status
        status = tk.Frame(self, bg="#071022")
        status.pack(fill="x", padx=12, pady=(10,0))
        self.current_lbl = tk.Label(status, text="Trying: (none)", fg="#ffd6a5", bg="#071022", font=("Courier", 12))
        self.current_lbl.pack(anchor="w", padx=8, pady=(8,4))
        stats_row = tk.Frame(status, bg="#071022")
        stats_row.pack(anchor="w", padx=8, pady=(0,8))
        self.attempts_lbl = tk.Label(stats_row, text="Attempts: 0", fg="#cfe8ff", bg="#071022")
        self.attempts_lbl.pack(side="left", padx=(0,14))
        self.elapsed_lbl = tk.Label(stats_row, text="Elapsed: 0.0s", fg="#cfe8ff", bg="#071022")
        self.elapsed_lbl.pack(side="left", padx=(0,14))

        # console
        console_frame = tk.Frame(self, bg="#0f1724")
        console_frame.pack(fill="both", expand=True, padx=12, pady=12)
        tk.Label(console_frame, text="Console:", fg="#dbeafe", bg="#0f1724").pack(anchor="w")
        self.console = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD, bg="#071018", fg="#d7ffd9", font=("Courier", 10))
        self.console.pack(fill="both", expand=True, pady=(6,0))
        self._log("Ready.")

    def _log(self, text):
        ts = time.strftime("%H:%M:%S")
        self.console.insert("end", f"[{ts}] {text}\n")
        self.console.see("end")

    def _clear_console(self):
        self.console.delete("1.0", "end")

    def _browse_zip(self):
        p = filedialog.askopenfilename(title="Select ZIP file", filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")])
        if p:
            self.zip_path.set(p)
            self._log(f"Selected ZIP: {p}")

    def _browse_wordlist(self):
        p = filedialog.askopenfilename(title="Select wordlist (.txt)", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if p:
            self.wordlist_path.set(p)
            self._log(f"Selected wordlist: {p}")

    def _load_default(self):
        if os.path.exists(DEFAULT_WORDLIST):
            self.wordlist_path.set(DEFAULT_WORDLIST)
            self._log(f"Loaded default: {DEFAULT_WORDLIST}")
        else:
            messagebox.showinfo("Not found", f"{DEFAULT_WORDLIST} not found. Please select a wordlist.")

    def start(self):
        zipf = self.zip_path.get().strip()
        wl = self.wordlist_path.get().strip()
        if not zipf or not os.path.isfile(zipf):
            messagebox.showerror("ZIP missing", "Please select a valid ZIP file.")
            return
        if not wl or not os.path.isfile(wl):
            messagebox.showerror("Wordlist missing", "Please select a valid wordlist (.txt).")
            return

        # prepare
        self._found = False
        self._found_details = None
        self._stop_event.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.console.delete("1.0", "end")
        self._log("Starting brute-force...")
        self._start_time = time.time()
        self._attempts = 0

        aes = detect_aes(zipf)
        if aes:
            self._log("Archive appears to use AES/strong encryption. unzip may not work — john/hashcat may be required.")

        # start worker thread
        self._worker = threading.Thread(target=self._worker_loop, args=(zipf, wl, aes), daemon=True)
        self._worker.start()

    def stop(self):
        if self._worker and self._worker.is_alive():
            self._stop_event.set()
            self._log("Stop requested...")

    def _worker_loop(self, zipfile_path, wordlist_path, aes_detected):
        # read wordlist with fallback encodings
        try:
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="strict") as fh:
                    lines = fh.readlines()
            except Exception:
                with open(wordlist_path, "r", encoding="latin-1", errors="replace") as fh:
                    lines = fh.readlines()
        except Exception as e:
            self._queue.put(("log", f"Failed to read wordlist: {e}"))
            self._queue.put(("worker_done", None))
            return

        total = len(lines)
        self._queue.put(("log", f"Total candidates: {total}"))

        for idx, raw in enumerate(lines, 1):
            if self._stop_event.is_set():
                self._queue.put(("log", "Worker stopped by user"))
                break

            pw = raw.rstrip("\r\n")
            pw = pw.strip()
            if pw.startswith(("'", '"')) and pw.endswith(("'", '"')) and len(pw) >= 2:
                pw = pw[1:-1]
            if not pw:
                continue

            self._attempts += 1
            # UI updates throttled
            if idx % 5 == 0:
                self._queue.put(("current", pw))
            if idx % 50 == 0:
                elapsed = time.time() - self._start_time
                self._queue.put(("stats", (self._attempts, elapsed)))

            # Try unzip
            if shutil.which(ZIP_CMD):
                ok, out = test_with_unzip(zipfile_path, pw)
                if ok:
                    self._found = True
                    self._found_details = (pw, "unzip", idx)
                    self._queue.put(("found", (pw, "unzip", idx)))
                    return

            # Try Python zipfile fallback
            ok2, out2 = test_with_zipfile(zipfile_path, pw)
            if ok2:
                self._found = True
                self._found_details = (pw, "zipfile", idx)
                self._queue.put(("found", (pw, "zipfile", idx)))
                return

            # Try 7z if present
            if shutil.which(SEVENZ_CMD):
                ok3, out3 = test_with_7z(zipfile_path, pw)
                if ok3:
                    self._found = True
                    self._found_details = (pw, "7z", idx)
                    self._queue.put(("found", (pw, "7z", idx)))
                    return

        # finished loop; not found
        if not self._found:
            # if AES detected, try john as last resort
            if aes_detected and shutil.which(ZIP2JOHN_CMD) and shutil.which(JOHN_CMD):
                self._queue.put(("log", "AES detected — trying zip2john + john fallback (may be slow)..."))
                found_pw = try_john_fallback(zipfile_path, wordlist_path, self._queue.put)
                if found_pw:
                    self._found = True
                    self._found_details = (found_pw, "john", len(lines))
                    self._queue.put(("found", (found_pw, "john", len(lines))))
                    return
            self._queue.put(("done", None))

        self._queue.put(("worker_done", None))

    def _process_queue(self):
        try:
            while True:
                typ, data = self._queue.get_nowait()
                if typ == "log":
                    self._log(data)
                elif typ == "current":
                    short = data if len(data) <= 60 else data[:57] + "..."
                    self.current_lbl.config(text=f"Trying: {short}")
                elif typ == "stats":
                    attempts, elapsed = data
                    self.attempts_lbl.config(text=f"Attempts: {attempts}")
                    self.elapsed_lbl.config(text=f"Elapsed: {elapsed:.1f}s")
                elif typ == "found":
                    pw, method, idx = data
                    self._log(f"Password found (method={method}) at candidate #{idx}")
                    # ensure worker stops
                    self._stop_event.set()
                    self._show_found_popup(pw, method)
                elif typ == "done":
                    if not self._found:
                        self._log("No matching password found in the wordlist.")
                        messagebox.showinfo("Result", "No matching password found in the wordlist.")
                elif typ == "worker_done":
                    self.start_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                    self.current_lbl.config(text="Trying: (none)")
                else:
                    self._log(f"Unknown queue item: {typ} - {data}")
        except queue.Empty:
            pass
        finally:
            self.after(120, self._process_queue)

    def _show_found_popup(self, password, method):
        win = tk.Toplevel(self)
        win.title("✅ Password Found")
        win.configure(bg="#0b1220")
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()

        tk.Label(win, text=f"Password found (method: {method})", font=("Inter", 12, "bold"), fg="#cfe8ff", bg="#0b1220").pack(pady=(12,6))
        tk.Label(win, text=password, font=("Courier", 22, "bold"), fg="#a7f3d0", bg="#0b1220").pack(pady=(0,12))

        btnf = tk.Frame(win, bg="#0b1220")
        btnf.pack(pady=(6,12))

        def copy_pw():
            try:
                self.clipboard_clear()
                self.clipboard_append(password)
                self._log("Password copied to clipboard.")
            except Exception as e:
                self._log(f"Copy failed: {e}")

        def extract_now():
            dest = filedialog.askdirectory(title="Select destination")
            if not dest:
                return
            self._log(f"Extracting to: {dest}")
            try:
                subprocess.run([ZIP_CMD, "-o", "-P", password, self.zip_path.get(), "-d", dest])
                messagebox.showinfo("Extracted", f"Files extracted to: {dest}")
            except Exception as e:
                messagebox.showerror("Extract error", str(e))
            win.destroy()

        ttk.Button(btnf, text="Copy Password", command=copy_pw).pack(side="left", padx=8)
        ttk.Button(btnf, text="Extract Now", command=extract_now).pack(side="left", padx=8)
        ttk.Button(btnf, text="Close", command=win.destroy).pack(side="left", padx=8)

        # center popup
        self.update_idletasks()
        w, h = 480, 200
        x = self.winfo_x() + (self.winfo_width() - w) // 2
        y = self.winfo_y() + (self.winfo_height() - h) // 2
        win.geometry(f"{w}x{h}+{max(x,0)}+{max(y,0)}")

        # ensure worker stop
        self._stop_event.set()
        win.wait_window()

# -------- Run --------
def main():
    if not shutil.which(ZIP_CMD):
        print(f"Note: '{ZIP_CMD}' not found. The tool will still try Python zipfile/7z if available.")
    app = ZipCrackerApp()
    app.mainloop()

if __name__ == "__main__":
    main()

