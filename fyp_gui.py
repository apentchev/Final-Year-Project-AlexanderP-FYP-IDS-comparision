#FYP IDS Pipeline — GUI Launcher
# Double-click this file to open the GUI.

import os
import sys
import json
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from datetime import datetime

# Default config
DEFAULT_ZEEK_ROOT = os.path.dirname(os.path.abspath(__file__)) #Sets data folder to wherever fyp_gui.py is saved
PYTHON_EXE = sys.executable
DEFAULT_SEED      = 42
DEFAULT_BALANCE   = 3
DEFAULT_TREES_RF  = 100
DEFAULT_TREES_IF  = 200

LABEL_COLOURS = {0: "#4CAF50", 1: "#F44336", 2: "#FF9800"}
LABEL_NAMES   = {0: "Benign", 1: "DoS", 2: "C2 Beacon"}

# Colours
BG       = "#1E1E2E"
BG2      = "#2A2A3E"
BG3      = "#313145"
ACCENT   = "#7C6AF7"
ACCENT2  = "#5E81F4"
GREEN    = "#50FA7B"
RED      = "#FF5555"
ORANGE   = "#FFB86C"
TEXT     = "#F8F8F2"
TEXT2    = "#AAAACC"
BORDER   = "#44445A"


class FYPLauncher(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FYP IDS Pipeline — GUI Launcher")
        self.geometry("1100x820")
        self.configure(bg=BG)
        self.resizable(True, True)

        self.sessions = {}          # name  label (0/1/2)
        self.dataset_dir = tk.StringVar()
        self.log_queue   = []

        self._build_ui()
        self._load_sessions_from_script()

    # UI construction
    def _build_ui(self): #
        # Constructs
        title_frame = tk.Frame(self, bg=ACCENT, height=50)
        title_frame.pack(fill="x")
        tk.Label(title_frame, text="FYP IDS ML Pipeline",
                 font=("Segoe UI", 16, "bold"), bg=ACCENT, fg=TEXT
                 ).pack(side="left", padx=20, pady=10)

        # Main layout
        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=15, pady=10)

        left  = tk.Frame(main, bg=BG, width=500)
        right = tk.Frame(main, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right.pack(side="right", fill="both", expand=True)

        self._build_status_bar()

        # LEFT: Config + Sessions
        self._build_config(left)
        self._build_sessions(left)

        # RIGHT: Steps + Log
        self._build_steps(right)
        self._build_log(right)

    def _card(self, parent, title):
        frame = tk.LabelFrame(parent, text=f"  {title}  ",
                              font=("Segoe UI", 10, "bold"),
                              fg=ACCENT2, bg=BG2, bd=1,
                              relief="solid", labelanchor="nw")
        frame.pack(fill="x", pady=(0, 10))
        return frame

    def _build_config(self, parent):
        card = self._card(parent, "⚙  Configuration")
        card.configure(bg=BG2)

        def row(label, var, default, col2_width=8):
            f = tk.Frame(card, bg=BG2)
            f.pack(fill="x", padx=12, pady=4)
            tk.Label(f, text=label, width=22, anchor="w",
                     fg=TEXT2, bg=BG2, font=("Segoe UI", 9)).pack(side="left")
            e = tk.Entry(f, textvariable=var, width=col2_width,
                         bg=BG3, fg=TEXT, insertbackground=TEXT,
                         relief="flat", font=("Segoe UI", 9))
            e.pack(side="left", padx=4)
            var.set(default)
            return e

        self.zeek_root = tk.StringVar()
        f = tk.Frame(card, bg=BG2)
        f.pack(fill="x", padx=12, pady=4)
        tk.Label(f, text="Zeek data root:", width=22, anchor="w",
                 fg=TEXT2, bg=BG2, font=("Segoe UI", 9)).pack(side="left")
        e = tk.Entry(f, textvariable=self.zeek_root, width=35,
                     bg=BG3, fg=TEXT, insertbackground=TEXT,
                     relief="flat", font=("Segoe UI", 9))
        e.pack(side="left", padx=4)
        self.zeek_root.set(DEFAULT_ZEEK_ROOT)
        tk.Button(f, text="Browse", command=self._browse_root,
                  bg=ACCENT, fg=TEXT, relief="flat",
                  font=("Segoe UI", 8), padx=6
                  ).pack(side="left")

        self.seed_var    = tk.StringVar()
        self.balance_var = tk.StringVar()
        self.trees_rf    = tk.StringVar()
        self.trees_if    = tk.StringVar()

        row("Random seed:", self.seed_var,    DEFAULT_SEED)
        row("DoS balance multiplier:", self.balance_var, DEFAULT_BALANCE)
        row("RF trees:", self.trees_rf,  DEFAULT_TREES_RF)
        row("IF trees:", self.trees_if,  DEFAULT_TREES_IF)

    def _build_sessions(self, parent):
        card = self._card(parent, "📂  Sessions (from 01_extract_features.py)")

        btn_row = tk.Frame(card, bg=BG2)
        btn_row.pack(fill="x", padx=12, pady=(6, 4))

        for label, colour, lval in [("+ Benign", GREEN, 0), ("+ DoS", RED, 1), ("+ C2", ORANGE, 2)]:
            tk.Button(btn_row, text=label,
                      command=lambda v=lval: self._add_session(v),
                      bg=colour, fg="#000", relief="flat",
                      font=("Segoe UI", 8, "bold"), padx=8, pady=3
                      ).pack(side="left", padx=3)

        tk.Button(btn_row, text="✕ Remove selected",
                  command=self._remove_session,
                  bg=BG3, fg=RED, relief="flat",
                  font=("Segoe UI", 8), padx=8, pady=3
                  ).pack(side="left", padx=3)

        tk.Button(btn_row, text="↻ Reload from script",
                  command=self._load_sessions_from_script,
                  bg=BG3, fg=ACCENT2, relief="flat",
                  font=("Segoe UI", 8), padx=8, pady=3
                  ).pack(side="right", padx=3)

        # Treeview
        cols = ("Session Name", "Label")
        self.tree = ttk.Treeview(card, columns=cols, show="headings", height=10)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background=BG3, foreground=TEXT,
                        fieldbackground=BG3, rowheight=22,
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading",
                        background=BG2, foreground=ACCENT2,
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", ACCENT)])

        self.tree.heading("Session Name", text="Session Name")
        self.tree.heading("Label", text="Label")
        self.tree.column("Session Name", width=340)
        self.tree.column("Label", width=90, anchor="center")

        sb = ttk.Scrollbar(card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=(0, 10))
        sb.pack(side="right", fill="y", pady=(0, 10), padx=(0, 6))

        self._refresh_tree()

    def _build_steps(self, parent):
        card = self._card(parent, "🚀  Run Pipeline Steps")

        steps = [
            ("Step 1 — Extract Features",
             "Reads Zeek conn.log files and builds the labelled dataset.",
             self._run_step1, ACCENT),
            ("Step 2 — Random Forest",
             "Trains supervised multiclass classifier. Requires Step 1 first.",
             self._run_step2, "#50FA7B"),
            ("Step 3 — Isolation Forest",
             "Trains unsupervised anomaly detector. Requires Step 1 first.",
             self._run_step3, ORANGE),
            ("Run All Steps",
             "Runs Steps 1 → 2 → 3 in sequence automatically.",
             self._run_all, "#FF79C6"),
        ]

        for title, desc, cmd, colour in steps:
            f = tk.Frame(card, bg=BG3, bd=0)
            f.pack(fill="x", padx=12, pady=5)
            tk.Label(f, text=title, font=("Segoe UI", 10, "bold"),
                     fg=colour, bg=BG3).pack(anchor="w", padx=10, pady=(8, 0))
            tk.Label(f, text=desc, font=("Segoe UI", 8),
                     fg=TEXT2, bg=BG3).pack(anchor="w", padx=10)
            tk.Button(f, text=f"▶  {title}",
                      command=cmd,
                      bg=colour, fg="#000" if colour != ACCENT else TEXT,
                      relief="flat", font=("Segoe UI", 9, "bold"),
                      padx=12, pady=5
                      ).pack(anchor="w", padx=10, pady=(4, 8))

        # Dataset selector for steps 2 & 3
        ds_frame = tk.Frame(card, bg=BG2)
        ds_frame.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(ds_frame, text="Dataset folder (for Steps 2 & 3):",
                 fg=TEXT2, bg=BG2, font=("Segoe UI", 9)
                 ).pack(side="left")
        tk.Entry(ds_frame, textvariable=self.dataset_dir, width=28,
                 bg=BG3, fg=TEXT, insertbackground=TEXT,
                 relief="flat", font=("Segoe UI", 9)
                 ).pack(side="left", padx=4)
        tk.Button(ds_frame, text="Browse",
                  command=self._browse_dataset,
                  bg=ACCENT, fg=TEXT, relief="flat",
                  font=("Segoe UI", 8), padx=6
                  ).pack(side="left")

    def _build_log(self, parent):
        card = self._card(parent, "📋  Output Log")
        card.pack(fill="both", expand=True, pady=(0, 10))

        btn_row = tk.Frame(card, bg=BG2)
        btn_row.pack(fill="x", padx=12, pady=(4, 0))
        tk.Button(btn_row, text="Clear log",
                  command=self._clear_log,
                  bg=BG3, fg=TEXT2, relief="flat",
                  font=("Segoe UI", 8), padx=8
                  ).pack(side="right")

        self.log = scrolledtext.ScrolledText(
            card, bg="#0D0D1A", fg=GREEN,
            font=("Consolas", 9), relief="flat",
            insertbackground=GREEN, wrap="word"
        )
        self.log.pack(fill="both", expand=True, padx=12, pady=(4, 10))
        self.log.tag_config("err",  foreground=RED)
        self.log.tag_config("info", foreground=ACCENT2)
        self.log.tag_config("ok",   foreground=GREEN)
        self.log.tag_config("warn", foreground=ORANGE)

    def _build_status_bar(self):
        self._status_frame = tk.Frame(self, bg=BG2, height=30)
        self._status_frame.pack(fill="x", side="bottom")
        self._spinner_label = tk.Label(
            self._status_frame, text="", fg=GREEN, bg=BG2,
            font=("Consolas", 11)
        )
        self._spinner_label.pack(side="left", padx=15)
        self._status_label = tk.Label(
            self._status_frame, text="Ready", fg=TEXT2, bg=BG2,
            font=("Segoe UI", 9)
        )
        self._status_label.pack(side="left")
        self._spinning = False
        self._spin_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self._spin_idx = 0

    def _start_spinner(self, msg="Running..."):
        self._spinning = True
        self._status_label.config(text=msg, fg=GREEN)
        self._animate_spinner()

    def _stop_spinner(self, msg="Ready"):
        self._spinning = False
        self._spinner_label.config(text="✓")
        self._status_label.config(text=msg, fg=TEXT2)

    def _animate_spinner(self):
        if not self._spinning:
            return
        self._spinner_label.config(text=self._spin_frames[self._spin_idx])
        self._spin_idx = (self._spin_idx + 1) % len(self._spin_frames)
        self.after(80, self._animate_spinner)

    # Session management
    def _load_sessions_from_script(self):
        """Try to parse SESSIONS dict from 01_extract_features.py automatically."""
        script = "01_extract_features.py"
        if not os.path.exists(script):
            self._log(f"[!] {script} not found — add sessions manually", "warn")
            return
        try:
            with open(script) as f:
                src = f.read()
            # Find SESSIONS = { ... }
            start = src.index("SESSIONS = {")
            end   = src.index("}", start) + 1
            block = src[start:end]
            # Safe eval
            local = {}
            exec(block, {}, local)
            self.sessions = dict(local["SESSIONS"])
            self._refresh_tree()
            self._log(f" Loaded {len(self.sessions)} sessions from {script}", "ok")
        except Exception as e:
            self._log(f" Could not auto-load sessions: {e}", "warn")

    def _refresh_tree(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for name, lval in self.sessions.items():
            lname = LABEL_NAMES.get(lval, str(lval))
            colour = LABEL_COLOURS.get(lval, "#888")
            self.tree.insert("", "end", values=(name, lname), tags=(lname,))
            self.tree.tag_configure(lname, foreground=colour)

    def _add_session(self, label_val):
        # Lets the user browse to the session folder
        folder = filedialog.askdirectory(
            title=f"Select session folder (label: {LABEL_NAMES[label_val]})",
            initialdir=self.zeek_root.get()
        )
        if not folder:
            return
        # Extract just the folder name, not the full path
        name = os.path.basename(folder)
        if name:
            self.sessions[name] = label_val
            self._refresh_tree()
            self._log(f" Added session: {name} → {LABEL_NAMES[label_val]}", "ok")

    def _remove_session(self):
        sel = self.tree.selection()
        if not sel:
            return
        for item in sel:
            name = self.tree.item(item, "values")[0]
            self.sessions.pop(name, None)
        self._refresh_tree()

    # ── Browsing ──────────────────────────────────────────────────────────────
    def _browse_root(self):
        d = filedialog.askdirectory(title="Select Zeek data root folder")
        if d:
            self.zeek_root.set(d)

    def _browse_dataset(self):
        d = filedialog.askdirectory(title="Select dataset run folder")
        if d:
            self.dataset_dir.set(d)

    # Running scripts
    def _build_step1_args(self):
        return [
            PYTHON_EXE, "01_extract_features.py",
            "--seed",    str(self.seed_var.get()),
            "--balance", str(self.balance_var.get()),
        ]

    def _build_step2_args(self, ds):
        return [
            PYTHON_EXE, "02_random_forest.py",
            "--dataset", ds,
            "--seed",    str(self.seed_var.get()),
            "--trees",   str(self.trees_rf.get()),
        ]

    def _build_step3_args(self, ds):
        return [
            PYTHON_EXE, "03_isolation_forest.py",
            "--dataset", ds,
            "--seed",    str(self.seed_var.get()),
            "--trees",   str(self.trees_if.get()),
        ]

    def _write_session_patch(self):
        config_path = "gui_sessions.json"
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(self.sessions, f, indent=2)
            self._log(f"[✓] Sessions written to {config_path}", "ok")
            return True
        except Exception as e:
            self._log(f"[ERROR] Could not write sessions: {e}", "err")
            return False

    def _run_command(self, args, on_done=None):
        """Run a command in a background thread, streaming output to log."""
        script_name = os.path.basename(args[1]) if len(args) > 1 else "script"
        self.after(0, lambda: self._start_spinner(f"Running {script_name}..."))
        def worker():
            self._log(f"\n Running: {' '.join(args[1:])}", "info")
            try:
                proc = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                last_run_id = None
                for line in proc.stdout:
                    line = line.rstrip()
                    if "[ERROR]" in line:
                        self._log(line, "err")
                    elif "[✓]" in line or "PASS" in line:
                        self._log(line, "ok")
                    elif "[!]" in line or "WARNING" in line:
                        self._log(line, "warn")
                    else:
                        self._log(line)
                    # Detect run ID from step 1 output
                    if "Run ID:" in line and "run_" in line:
                        parts = line.split("run_")
                        if len(parts) > 1:
                            last_run_id = "run_" + parts[1].strip()

                proc.wait()
                if proc.returncode == 0:
                    self._log("\n[✓] Completed successfully!", "ok")
                else:
                    self._log(f"\n[✗] Exited with code {proc.returncode}", "err")

                self.after(0, lambda: self._stop_spinner("Done" if proc.returncode == 0 else "Error"))
                if on_done:
                    self.after(0, lambda: on_done(last_run_id))
            except Exception as e:
                self._log(f"\n[✗] Error: {e}", "err")

        threading.Thread(target=worker, daemon=True).start()

    def _run_step1(self):
        if not self.sessions:
            messagebox.showwarning("No sessions", "Add at least one session before running.")
            return
        if not self._write_session_patch():
            return

        def on_done(run_id):
            if run_id:
                ds = os.path.join("dataset", run_id)
                self.dataset_dir.set(ds)
                self._log(f"\n Dataset saved to: {ds}", "ok")
                self._log("You can now run Step 2 and Step 3.", "info")

        self._run_command(self._build_step1_args(), on_done=on_done)

    def _run_step2(self):
        ds = self.dataset_dir.get().strip()
        if not ds:
            messagebox.showwarning("No dataset", "Run Step 1 first, or select a dataset folder.")
            return
        self._run_command(self._build_step2_args(ds))

    def _run_step3(self):
        ds = self.dataset_dir.get().strip()
        if not ds:
            messagebox.showwarning("No dataset", "Run Step 1 first, or select a dataset folder.")
            return
        self._run_command(self._build_step3_args(ds))

    def _run_all(self):
        if not self.sessions:
            messagebox.showwarning("No sessions", "Add at least one session before running.")
            return
        if not self._write_session_patch():
            return

        def after_step1(run_id):
            if not run_id:
                self._log(" Could not determine dataset from Step 1 output", "err")
                return
            ds = os.path.join("dataset", run_id)
            self.dataset_dir.set(ds)
            self._log(f"\n Starting Step 2 with dataset: {ds}", "info")

            def after_step2(_):
                self._log("\n Starting Step 3...", "info")
                self._run_command(self._build_step3_args(ds))

            self._run_command(self._build_step2_args(ds), on_done=after_step2)

        self._run_command(self._build_step1_args(), on_done=after_step1)

    # Logging
    def _log(self, msg, tag=""):
        def _write():
            self.log.configure(state="normal")
            self.log.insert("end", msg + "\n", tag or "")
            self.log.see("end")
            self.log.configure(state="disabled")
        self.after(0, _write)

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")


# Entry point
if __name__ == "__main__":
    import tkinter.simpledialog  # needed for askstring
    app = FYPLauncher()
    app.mainloop()
