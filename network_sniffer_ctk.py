#!/usr/bin/env python3
"""
CodeAlpha - Cyber Security Internship
Task 1 : Modern Network Sniffer - CustomTkinter GUI (English)

Modern GUI built with CustomTkinter (rounded widgets, dark/light themes).
Packet capture powered by scapy. Detects TCP, UDP, ICMP, ARP, DNS, HTTP
and HTTPS/TLS traffic.

Requirements:
    pip install scapy customtkinter
    Run with administrator / root privileges (sudo on Kali Linux)
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import csv
import math
from datetime import datetime
from collections import Counter

try:
    import customtkinter as ctk
except ImportError:
    print("[!] Error: the 'customtkinter' library is required.")
    print("[*] Install it with: pip install customtkinter")
    sys.exit(1)

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
        Raw, get_if_list, wrpcap
    )
except ImportError:
    print("[!] Error: the 'scapy' library is required.")
    print("[*] Install it with: pip install scapy")
    sys.exit(1)

# Global CustomTkinter theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

STAT_KEYS = ["Total", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "Other"]
STAT_COLORS = {
    "Total": "#89b4fa",
    "TCP": "#a6e3a1",
    "UDP": "#f9e2af",
    "ICMP": "#fab387",
    "ARP": "#94e2d5",
    "DNS": "#74c7ec",
    "HTTP": "#f5c2e7",
    "HTTPS": "#eba0ac",
    "Other": "#cba6f7",
}

# Friendly filter label -> BPF expression (None = no filter)
FILTER_MAP = {
    "All": None,
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "arp": "arp",
    "dns (port 53)": "port 53",
    "http (port 80)": "port 80",
    "https/tls (port 443)": "port 443",
}


class ModernSaveDialog(ctk.CTkToplevel):
    """A dark-themed, in-app file-save dialog matching the app's own style,
    replacing the plain native OS file picker."""

    def __init__(self, parent, title="Save File", initialfile="file.txt",
                 filetypes=(("All files", "*.*"),), initialdir=None):
        super().__init__(parent)
        self.filetypes = filetypes
        self.result = None
        self._entries = []

        self.current_dir = initialdir or os.path.expanduser("~/Desktop")
        if not os.path.isdir(self.current_dir):
            self.current_dir = os.path.expanduser("~")

        first_ext = filetypes[0][1].replace("*", "") if filetypes else ""
        self.selected_ext = first_ext

        self.title(title)
        self.geometry("560x460")
        self.minsize(480, 380)
        self.configure(fg_color="#181926")
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._build_ui(title, initialfile)
        self._populate_list()

        self.after(10, self._center_on_parent)
        self.filename_entry.focus_set()
        self.filename_entry.icursor(tk.END)

    # -- layout -----------------------------------------------------
    def _build_ui(self, title, initialfile):
        header = ctk.CTkFrame(self, height=44, corner_radius=0, fg_color="#12131c")
        header.pack(fill="x")
        ctk.CTkLabel(header, text=f"💾  {title}", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#89b4fa").pack(side="left", padx=15, pady=10)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=15, pady=10)

        # Directory bar
        dir_row = ctk.CTkFrame(body, fg_color="transparent")
        dir_row.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(dir_row, text="Directory:", width=75, anchor="w").pack(side="left")
        self.dir_var = tk.StringVar(value=self.current_dir)
        self.dir_entry = ctk.CTkEntry(dir_row, textvariable=self.dir_var)
        self.dir_entry.pack(side="left", fill="x", expand=True, padx=(5, 5))
        self.dir_entry.bind("<Return>", lambda e: self._go_to_typed_dir())
        ctk.CTkButton(dir_row, text="⬆", width=32, fg_color="#3a3b5c", hover_color="#4f507d",
                      command=self._go_up).pack(side="left", padx=(0, 4))
        ctk.CTkButton(dir_row, text="🏠", width=32, fg_color="#3a3b5c", hover_color="#4f507d",
                      command=self._go_home).pack(side="left")

        # File / folder browser list
        list_frame = ctk.CTkFrame(body, fg_color="#1e1e2e", corner_radius=8)
        list_frame.pack(fill="both", expand=True, pady=(0, 10))

        self.listbox = tk.Listbox(
            list_frame, bg="#1e1e2e", fg="#cdd6f4", selectbackground="#45475a",
            selectforeground="#ffffff", highlightthickness=0, borderwidth=0,
            font=("Segoe UI", 11), activestyle="none"
        )
        self.listbox.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        list_scroll = ctk.CTkScrollbar(list_frame, command=self.listbox.yview)
        list_scroll.pack(side="right", fill="y", pady=6)
        self.listbox.configure(yscrollcommand=list_scroll.set)
        self.listbox.bind("<Double-Button-1>", self._on_item_double_click)
        self.listbox.bind("<<ListboxSelect>>", self._on_item_select)

        # File name row
        fname_row = ctk.CTkFrame(body, fg_color="transparent")
        fname_row.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(fname_row, text="File name:", width=75, anchor="w").pack(side="left")
        self.filename_var = tk.StringVar(value=initialfile)
        self.filename_entry = ctk.CTkEntry(fname_row, textvariable=self.filename_var)
        self.filename_entry.pack(side="left", fill="x", expand=True, padx=(5, 0))
        self.filename_entry.bind("<Return>", lambda e: self._on_save())

        # File type row
        type_row = ctk.CTkFrame(body, fg_color="transparent")
        type_row.pack(fill="x")
        ctk.CTkLabel(type_row, text="Files of type:", width=75, anchor="w").pack(side="left")
        type_labels = [f"{desc} ({pattern})" for desc, pattern in self.filetypes]
        self.type_var = tk.StringVar(value=type_labels[0] if type_labels else "")
        self.type_menu = ctk.CTkOptionMenu(type_row, values=type_labels, variable=self.type_var,
                                            command=self._on_type_change, width=220)
        self.type_menu.pack(side="left", padx=(5, 0))

        # Buttons
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(0, 15))
        ctk.CTkButton(btn_row, text="Cancel", fg_color="#4f5b66", hover_color="#343d46",
                      command=self._on_cancel).pack(side="right")
        ctk.CTkButton(btn_row, text="Save", fg_color="#2eb872", hover_color="#1d8f53",
                      font=ctk.CTkFont(weight="bold"), command=self._on_save).pack(side="right", padx=(0, 10))

    # -- helpers ------------------------------------------------------
    def _center_on_parent(self):
        self.update_idletasks()
        try:
            px, py = self.master.winfo_rootx(), self.master.winfo_rooty()
            pw, ph = self.master.winfo_width(), self.master.winfo_height()
            w, h = self.winfo_width(), self.winfo_height()
            self.geometry(f"+{px + (pw - w) // 2}+{py + (ph - h) // 2}")
        except Exception:
            pass

    def _on_type_change(self, val):
        type_labels = [f"{desc} ({pattern})" for desc, pattern in self.filetypes]
        if val in type_labels:
            idx = type_labels.index(val)
            ext = self.filetypes[idx][1].replace("*", "")
            self.selected_ext = ext
            if ext and ext != ".":
                name, _ = os.path.splitext(self.filename_var.get())
                self.filename_var.set(name + ext)
        self._populate_list()

    def _populate_list(self):
        self.listbox.delete(0, tk.END)
        self.dir_var.set(self.current_dir)
        self._entries = []
        try:
            entries = sorted(
                os.listdir(self.current_dir),
                key=lambda x: (not os.path.isdir(os.path.join(self.current_dir, x)), x.lower())
            )
        except Exception:
            entries = []

        for entry in entries:
            if entry.startswith("."):
                continue
            full = os.path.join(self.current_dir, entry)
            if os.path.isdir(full):
                self.listbox.insert(tk.END, f"📁  {entry}")
                self._entries.append((entry, True))
            else:
                if self.selected_ext and self.selected_ext not in (".*", "") and \
                        not entry.lower().endswith(self.selected_ext.lower()):
                    continue
                self.listbox.insert(tk.END, f"📄  {entry}")
                self._entries.append((entry, False))

    def _on_item_double_click(self, _event):
        sel = self.listbox.curselection()
        if not sel:
            return
        name, is_dir = self._entries[sel[0]]
        if is_dir:
            self.current_dir = os.path.join(self.current_dir, name)
            self._populate_list()
        else:
            self.filename_var.set(name)
            self._on_save()

    def _on_item_select(self, _event):
        sel = self.listbox.curselection()
        if not sel:
            return
        name, is_dir = self._entries[sel[0]]
        if not is_dir:
            self.filename_var.set(name)

    def _go_up(self):
        parent = os.path.dirname(self.current_dir.rstrip(os.sep))
        if parent and os.path.isdir(parent):
            self.current_dir = parent
            self._populate_list()

    def _go_home(self):
        home = os.path.expanduser("~")
        if os.path.isdir(home):
            self.current_dir = home
            self._populate_list()

    def _go_to_typed_dir(self):
        typed = self.dir_var.get().strip()
        if os.path.isdir(typed):
            self.current_dir = typed
            self._populate_list()
        else:
            messagebox.showerror("Error", "Directory does not exist.")

    def _on_save(self):
        filename = self.filename_var.get().strip()
        if not filename:
            messagebox.showerror("Error", "Please enter a file name.")
            return
        if self.selected_ext and self.selected_ext not in (".*", "") and \
                not filename.lower().endswith(self.selected_ext.lower()):
            filename += self.selected_ext

        full_path = os.path.join(self.current_dir, filename)
        if os.path.exists(full_path):
            if not messagebox.askyesno("Confirm Overwrite", f"'{filename}' already exists.\nDo you want to replace it?"):
                return
        self.result = full_path
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


def ask_save_file(parent, title, initialfile, filetypes, initialdir=None):
    """Opens the modern in-app save dialog and blocks until it is closed."""
    dialog = ModernSaveDialog(parent, title=title, initialfile=initialfile,
                               filetypes=filetypes, initialdir=initialdir)
    parent.wait_window(dialog)
    return dialog.result


class ModernNetworkSnifferGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        ctk.set_widget_scaling(0.9)
        ctk.set_window_scaling(0.9)

        self.title("🛡️ NetSniffer Pro - Network Analyzer")
        self.geometry("1180x800")
        self.minsize(1080, 740)

        # Capture state
        self.sniffing = False
        self.sniff_thread = None
        self.packet_count = 0

        self.stats = {key: 0 for key in STAT_KEYS}

        # Storage
        self.packets_data = {}   # num -> (formatted_details, raw_payload_bytes)
        self.raw_packets = []    # raw scapy packets (pcap export)
        self.all_rows = []       # every captured row (for search/filter)

        # Search state - a real StringVar bound live to the entry
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)

        self.build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ==========================================
        # 1. SIDEBAR
        # ==========================================
        self.sidebar_frame = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(11, weight=1)

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="🛡️ NetSniffer Pro",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(15, 2))

        self.subtitle_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="CodeAlpha Cybersecurity",
            font=ctk.CTkFont(size=12, slant="italic"),
            text_color="gray"
        )
        self.subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 10))

        self.iface_label = ctk.CTkLabel(self.sidebar_frame, text="Network Interface:", anchor="w")
        self.iface_label.grid(row=2, column=0, padx=20, pady=(5, 0), sticky="w")

        try:
            interfaces = get_if_list()
        except Exception:
            interfaces = []

        self.iface_combo = ctk.CTkComboBox(
            self.sidebar_frame,
            values=interfaces if interfaces else ["No interface found"],
            width=200
        )
        self.iface_combo.grid(row=3, column=0, padx=20, pady=(3, 8))
        if interfaces:
            self.iface_combo.set(interfaces[0])

        self.filter_label = ctk.CTkLabel(self.sidebar_frame, text="Protocol Filter:", anchor="w")
        self.filter_label.grid(row=4, column=0, padx=20, pady=(3, 0), sticky="w")

        self.filter_combo = ctk.CTkComboBox(
            self.sidebar_frame,
            values=list(FILTER_MAP.keys()),
            width=200
        )
        self.filter_combo.grid(row=5, column=0, padx=20, pady=(3, 10))
        self.filter_combo.set("All")

        self.start_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="▶ Start Capture",
            fg_color="#2eb872",
            hover_color="#1d8f53",
            font=ctk.CTkFont(weight="bold"),
            command=self.start_sniffing
        )
        self.start_btn.grid(row=6, column=0, padx=20, pady=5)

        self.stop_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="■ Stop Capture",
            fg_color="#e05252",
            hover_color="#b83535",
            font=ctk.CTkFont(weight="bold"),
            command=self.stop_sniffing,
            state="disabled"
        )
        self.stop_btn.grid(row=7, column=0, padx=20, pady=5)

        self.clear_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="🗑 Clear Grid",
            fg_color="#4f5b66",
            hover_color="#343d46",
            command=self.clear_table
        )
        self.clear_btn.grid(row=8, column=0, padx=20, pady=5)

        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=9, column=0, padx=20, pady=(15, 0), sticky="w")
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=["Dark", "Light", "System"],
            command=self.change_appearance_mode
        )
        self.appearance_mode_optionemenu.grid(row=10, column=0, padx=20, pady=(2, 10))

        # ==========================================
        # 2. MAIN AREA
        # ==========================================
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=15, pady=15)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)  # Table
        self.main_frame.grid_rowconfigure(3, weight=0)  # Details

        # --- 2.1 Stats dashboard (wraps into rows of 5 cards) ---
        self.stats_frame = ctk.CTkFrame(self.main_frame)
        self.stats_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))

        cols = 5
        for i in range(cols):
            self.stats_frame.grid_columnconfigure(i, weight=1)

        self.stat_cards = {}
        for index, name in enumerate(STAT_KEYS):
            color = STAT_COLORS[name]
            r, c = divmod(index, cols)
            card = ctk.CTkFrame(self.stats_frame, fg_color="#2e303e", corner_radius=8)
            card.grid(row=r, column=c, padx=10, pady=10, sticky="nsew")

            title_lbl = ctk.CTkLabel(card, text=name.upper(), font=ctk.CTkFont(size=10, weight="bold"), text_color="gray")
            title_lbl.pack(pady=(5, 0))

            val_lbl = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=20, weight="bold"), text_color=color)
            val_lbl.pack(pady=(2, 5))

            self.stat_cards[name] = val_lbl

        # --- 2.2 Live search bar ---
        self.search_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.search_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        self.search_entry = ctk.CTkEntry(
            self.search_frame,
            textvariable=self.search_var,
            placeholder_text="Search by IP, port, protocol...",
            width=320,
            height=28
        )
        self.search_entry.pack(side="left", padx=(5, 10))

        self.clear_search_btn = ctk.CTkButton(
            self.search_frame, text="✕", width=28, height=28,
            fg_color="#4f5b66", hover_color="#343d46",
            command=lambda: self.search_var.set("")
        )
        self.clear_search_btn.pack(side="left")

        self.search_status_lbl = ctk.CTkLabel(
            self.search_frame,
            text="",
            font=ctk.CTkFont(size=11, slant="italic"),
            text_color="#89b4fa"
        )
        self.search_status_lbl.pack(side="left", padx=10)

        # --- 2.3 Table (Treeview) ---
        self.table_container = ctk.CTkFrame(self.main_frame)
        self.table_container.grid(row=2, column=0, sticky="nsew", pady=(0, 15))
        self.table_container.grid_columnconfigure(0, weight=1)
        self.table_container.grid_rowconfigure(0, weight=1)

        self.tree_style = ttk.Style()
        self.tree_style.theme_use("default")
        self.tree_style.configure("Treeview",
            background="#1e1e2e", foreground="#cdd6f4", fieldbackground="#1e1e2e",
            rowheight=26, borderwidth=0, font=("Consolas", 10))
        self.tree_style.map("Treeview", background=[("selected", "#45475a")])
        self.tree_style.configure("Treeview.Heading",
            background="#313244", foreground="#cdd6f4", relief="flat", font=("Consolas", 10, "bold"))
        self.tree_style.map("Treeview.Heading", background=[("active", "#45475a")])

        columns = ("num", "time", "src", "dst", "proto", "sport", "dport", "info")
        self.tree = ttk.Treeview(self.table_container, columns=columns, show="headings", style="Treeview")
        self.tree.grid(row=0, column=0, sticky="nsew")

        headers = {
            "num": "No.", "time": "Time", "src": "Source IP", "dst": "Destination IP",
            "proto": "Protocol", "sport": "Src Port", "dport": "Dst Port", "info": "Info"
        }
        widths = {"num": 50, "time": 90, "src": 150, "dst": 150, "proto": 80,
                  "sport": 80, "dport": 80, "info": 220}
        for col in columns:
            self.tree.heading(col, text=headers[col])
            anchor = tk.W if col == "info" else tk.CENTER
            self.tree.column(col, width=widths[col], anchor=anchor)

        self.scrollbar = ctk.CTkScrollbar(self.table_container, orientation="vertical", command=self.tree.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.tree.bind("<Double-1>", self.show_packet_details)
        self.tree.bind("<<TreeviewSelect>>", self.on_row_select)

        for proto_name in ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "OTHER"]:
            self.tree.tag_configure(proto_name, foreground=STAT_COLORS.get(
                proto_name if proto_name != "OTHER" else "Other", "#cdd6f4"))

        # --- 2.4 Details / Payload viewer ---
        self.details_tab = ctk.CTkTabview(self.main_frame, height=210, command=self.on_tab_change)
        self.details_tab.grid(row=3, column=0, sticky="ew")

        self.tab_info = self.details_tab.add("ℹ️ Info")
        self.tab_payload = self.details_tab.add("📝 Payload")
        self.tab_exports = self.details_tab.add("💾 Exports & Stats")

        self.info_text = ctk.CTkTextbox(self.tab_info, font=("Consolas", 11), wrap="word")
        self.info_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.info_text.insert("0.0", "Double-click on a row to see detailed packet analysis.")
        self.info_text.configure(state="disabled")

        self.payload_controls = ctk.CTkFrame(self.tab_payload, fg_color="transparent", height=35)
        self.payload_controls.pack(fill="x", padx=5, pady=(5, 0))

        self.payload_mode_btn = ctk.CTkSegmentedButton(
            self.payload_controls,
            values=["UTF-8 Text", "Hex Dump", "Analysis"],
            command=self.update_payload_view
        )
        self.payload_mode_btn.pack(side="left", padx=5)
        self.payload_mode_btn.set("UTF-8 Text")

        self.payload_text = ctk.CTkTextbox(self.tab_payload, font=("Consolas", 10), wrap="none")
        self.payload_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.payload_text.insert("0.0", "Select a packet to visualize its payload.")
        self.payload_text.configure(state="disabled")

        self.exports_grid = ctk.CTkFrame(self.tab_exports, fg_color="transparent")
        self.exports_grid.pack(fill="both", expand=True, padx=10, pady=10)
        self.exports_grid.columnconfigure(0, weight=3)
        self.exports_grid.columnconfigure(1, weight=2)
        self.exports_grid.rowconfigure(0, weight=1)

        self.left_export_pane = ctk.CTkFrame(self.exports_grid, fg_color="transparent")
        self.left_export_pane.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.left_export_pane.rowconfigure(0, weight=1)
        self.left_export_pane.rowconfigure(1, weight=1)
        self.left_export_pane.columnconfigure(0, weight=1)

        self.csv_card = ctk.CTkFrame(self.left_export_pane, border_width=1, border_color="#3e3f5c")
        self.csv_card.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
        ctk.CTkLabel(self.csv_card, text="CSV Report", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=15, pady=(8, 2))
        ctk.CTkLabel(self.csv_card, text="Export all grid entries into CSV spreadsheet format.",
                     font=ctk.CTkFont(size=10), text_color="gray").pack(anchor="w", padx=15, pady=(0, 5))
        ctk.CTkButton(self.csv_card, text="Export...", font=ctk.CTkFont(size=11, weight="bold"), height=24, width=100,
                      fg_color="#3a3b5c", hover_color="#4f507d", command=self.export_csv).pack(anchor="e", padx=15, pady=(0, 8))

        self.pcap_card = ctk.CTkFrame(self.left_export_pane, border_width=1, border_color="#3e3f5c")
        self.pcap_card.grid(row=1, column=0, sticky="nsew", pady=(5, 0))
        ctk.CTkLabel(self.pcap_card, text="PCAP Capture", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=15, pady=(8, 2))
        ctk.CTkLabel(self.pcap_card, text="Export raw packet data in Wireshark (.pcap) format.",
                     font=ctk.CTkFont(size=10), text_color="gray").pack(anchor="w", padx=15, pady=(0, 5))
        ctk.CTkButton(self.pcap_card, text="Export...", font=ctk.CTkFont(size=11, weight="bold"), height=24, width=100,
                      fg_color="#3a3b5c", hover_color="#4f507d", command=self.export_pcap).pack(anchor="e", padx=15, pady=(0, 8))

        self.right_stats_pane = ctk.CTkFrame(self.exports_grid, border_width=1, border_color="#3e3f5c", fg_color="#181926")
        self.right_stats_pane.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        ctk.CTkLabel(self.right_stats_pane, text="Session Summary", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#89b4fa").pack(anchor="w", padx=15, pady=(10, 5))
        self.stats_summary_label = ctk.CTkLabel(
            self.right_stats_pane,
            text="No session data available.\nStart capturing packets first.",
            justify="left", font=ctk.CTkFont(family="Consolas", size=11), anchor="w"
        )
        self.stats_summary_label.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        # Status bar
        self.status_bar = ctk.CTkFrame(self, height=25, corner_radius=0)
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.status_label = ctk.CTkLabel(self.status_bar, text="Status: Inactive", text_color="#f38ba8",
                                          font=ctk.CTkFont(size=11, weight="bold"))
        self.status_label.pack(side="left", padx=20)
        self.count_label = ctk.CTkLabel(self.status_bar, text="Packets: 0", font=ctk.CTkFont(size=11))
        self.count_label.pack(side="right", padx=20)

    # ------------------------------------------------------------------
    # Appearance
    # ------------------------------------------------------------------
    def change_appearance_mode(self, new_mode):
        ctk.set_appearance_mode(new_mode)
        bg_color = "#2e303e" if new_mode.lower() == "dark" else "#f2f2f2"
        for card_val in self.stat_cards.values():
            card_val.master.configure(fg_color=bg_color)

        if new_mode.lower() == "light":
            self.tree_style.configure("Treeview", background="#ffffff", foreground="#313244", fieldbackground="#ffffff")
            self.tree_style.configure("Treeview.Heading", background="#e6e6e6", foreground="#313244")
        else:
            self.tree_style.configure("Treeview", background="#1e1e2e", foreground="#cdd6f4", fieldbackground="#1e1e2e")
            self.tree_style.configure("Treeview.Heading", background="#313244", foreground="#cdd6f4")

    # ------------------------------------------------------------------
    # Live search / filtering
    # ------------------------------------------------------------------
    def _packet_matches_query(self, row, query):
        if not query:
            return True
        query = query.strip().lower()
        return any(query in str(field).lower() for field in row)

    def _on_search_change(self, *_args):
        """Fires on every keystroke (StringVar trace) - always re-applies the filter."""
        query = self.search_var.get()

        for item in self.tree.get_children():
            self.tree.delete(item)

        visible_count = 0
        for row in self.all_rows:
            if self._packet_matches_query(row, query):
                proto = row[4]
                self.tree.insert("", tk.END, values=row, tags=(proto,))
                visible_count += 1

        if self.tree.get_children():
            self.tree.yview_moveto(1)

        self._update_search_status_label(visible_count)

    def _update_search_status_label(self, visible_count=None):
        total_count = len(self.all_rows)
        query = self.search_var.get().strip()

        if not query:
            self.search_status_lbl.configure(text="")
            return

        if visible_count is None:
            visible_count = sum(1 for row in self.all_rows if self._packet_matches_query(row, query))

        self.search_status_lbl.configure(text=f"Showing {visible_count} of {total_count} packets")

    # ------------------------------------------------------------------
    # Payload viewer
    # ------------------------------------------------------------------
    def update_payload_view(self, mode=None):
        if mode is None:
            mode = self.payload_mode_btn.get()

        selected = self.tree.selection()
        if not selected:
            return

        item = self.tree.item(selected[0])
        try:
            num = int(item["values"][0])
        except (ValueError, IndexError):
            return

        if num not in self.packets_data:
            return

        _, raw_payload = self.packets_data[num]

        self.payload_text.configure(state="normal")
        self.payload_text.delete("0.0", tk.END)

        if mode == "UTF-8 Text":
            if raw_payload:
                try:
                    decoded = raw_payload.decode('utf-8', errors='replace')
                except Exception:
                    decoded = str(raw_payload)
            else:
                decoded = "No payload"
            self.payload_text.insert("0.0", decoded)

        elif mode == "Hex Dump":
            self.payload_text.insert("0.0", self.get_hex_dump(raw_payload))

        elif mode == "Analysis":
            self.payload_text.insert("0.0", self.get_payload_analysis(raw_payload))

        self.payload_text.configure(state="disabled")

    def get_hex_dump(self, payload):
        if not payload:
            return "No payload data"
        result = []
        for i in range(0, len(payload), 16):
            chunk = payload[i:i + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(47)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            result.append(f"{i:04X}  {hex_part}  |{ascii_part}|")
        return "\n".join(result)

    def get_payload_analysis(self, payload):
        if not payload:
            return "No payload data"

        size = len(payload)
        printable_count = sum(1 for b in payload if 32 <= b < 127 or b in (9, 10, 13))
        ratio = (printable_count / size) * 100

        entropy = 0.0
        counts = {}
        for b in payload:
            counts[b] = counts.get(b, 0) + 1
        for count in counts.values():
            p = count / size
            entropy -= p * math.log2(p)

        nature = "Binary data"
        if ratio > 85:
            nature = "Plain text / Cleartext"
        elif entropy > 7.2:
            nature = "Encrypted or Compressed data (TLS/SSH/ZIP)"
        elif ratio < 10 and entropy < 3.0:
            nature = "Structured binary headers / Null-padded data"

        return (
            f"=== PAYLOAD STATISTICAL ANALYSIS ===\n\n"
            f" Payload Size                : {size} bytes\n"
            f" Printable Character Ratio   : {ratio:.2f} %\n"
            f" Entropy (Randomness)        : {entropy:.4f} (maximum 8.0)\n\n"
            f" [!] Suspected Nature        : {nature}\n"
        )

    # ------------------------------------------------------------------
    # Session-wide stats
    # ------------------------------------------------------------------
    def on_tab_change(self):
        if self.details_tab.get() == "💾 Exports & Stats":
            self.update_session_stats()

    def update_session_stats(self):
        if not self.raw_packets:
            self.stats_summary_label.configure(text="No session data available.\nStart capturing packets first.")
            return

        src_ips, dst_ips = [], []
        for packet in self.raw_packets:
            if IP in packet:
                src_ips.append(packet[IP].src)
                dst_ips.append(packet[IP].dst)

        if not src_ips:
            self.stats_summary_label.configure(text="No IP packets captured yet (ARP traffic has no IP layer).")
            return

        unique_src = len(set(src_ips))
        unique_dst = len(set(dst_ips))
        top_src = Counter(src_ips).most_common(1)[0][0]
        top_dst = Counter(dst_ips).most_common(1)[0][0]
        iface = self.iface_combo.get()

        summary = (
            f" Active interface: {iface}\n\n"
            f" Unique Source IPs: {unique_src}\n"
            f" Unique Dest IPs: {unique_dst}\n\n"
            f" Top Source IP: {top_src}\n"
            f" Top Destination IP: {top_dst}"
        )
        self.stats_summary_label.configure(text=summary)

    # ------------------------------------------------------------------
    # Capture logic
    # ------------------------------------------------------------------
    def start_sniffing(self):
        self.sniffing = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_label.configure(text="Status: Sniffing active...", text_color="#a6e3a1")
        self.iface_combo.configure(state="disabled")
        self.filter_combo.configure(state="disabled")

        self.sniff_thread = threading.Thread(target=self.sniff_loop, daemon=True)
        self.sniff_thread.start()

    def sniff_loop(self):
        iface = self.iface_combo.get()
        if iface in ("No interface found", ""):
            iface = None

        bpf_filter = FILTER_MAP.get(self.filter_combo.get())

        try:
            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=self.process_packet,
                stop_filter=lambda p: not self.sniffing,
                store=False
            )
        except PermissionError:
            self.after(0, lambda: messagebox.showerror(
                "Error", "Insufficient permissions.\nOn Kali Linux, run the program with 'sudo'."
            ))
            self.after(0, self.stop_sniffing)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.after(0, self.stop_sniffing)

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.iface_combo.configure(state="normal")
        self.filter_combo.configure(state="normal")
        self.status_label.configure(text="Status: Stopped", text_color="#f38ba8")

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.info_text.configure(state="normal")
        self.info_text.delete("0.0", tk.END)
        self.info_text.insert("0.0", "Double-click on a row to see detailed packet analysis.")
        self.info_text.configure(state="disabled")

        self.payload_text.configure(state="normal")
        self.payload_text.delete("0.0", tk.END)
        self.payload_text.insert("0.0", "Select a packet to visualize its payload.")
        self.payload_text.configure(state="disabled")

        self.packets_data.clear()
        self.raw_packets.clear()
        self.all_rows.clear()
        self.packet_count = 0

        # Reset search (setting the var fires the trace and clears the tree view too)
        self.search_var.set("")

        for key in self.stats:
            self.stats[key] = 0
            self.stat_cards[key].configure(text="0")

        self.count_label.configure(text="Packets: 0")
        self.update_session_stats()

    # ------------------------------------------------------------------
    # Packet classification & processing
    # ------------------------------------------------------------------
    def _classify(self, packet):
        """Returns (proto, sport, dport, src, dst, info) for a captured packet."""
        # ARP has no IP layer, handle it first
        if packet.haslayer(ARP):
            arp = packet[ARP]
            op = "who-has" if arp.op == 1 else "is-at" if arp.op == 2 else str(arp.op)
            info = f"{op} {arp.pdst} ? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} is-at {arp.hwsrc}"
            return "ARP", "", "", arp.psrc, arp.pdst, info

        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src, dst = ip_layer.src, ip_layer.dst
        sport = dport = ""
        info = ""

        if packet.haslayer(DNS):
            dns = packet[DNS]
            sport = packet[UDP].sport if packet.haslayer(UDP) else ""
            dport = packet[UDP].dport if packet.haslayer(UDP) else ""
            if dns.qdcount and dns.qd is not None:
                qname = dns.qd.qname.decode(errors="replace") if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                info = f"{'Response' if dns.qr == 1 else 'Query'}: {qname}"
            else:
                info = "Response" if dns.qr == 1 else "Query"
            return "DNS", sport, dport, src, dst, info

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            sport, dport = tcp_layer.sport, tcp_layer.dport
            if sport == 80 or dport == 80:
                proto = "HTTP"
                info = self._peek_http(packet)
            elif sport == 443 or dport == 443:
                proto = "HTTPS"
                info = "Encrypted TLS/SSL traffic"
            else:
                proto = "TCP"
                info = f"Flags={tcp_layer.flags}"
            return proto, sport, dport, src, dst, info

        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            sport, dport = udp_layer.sport, udp_layer.dport
            return "UDP", sport, dport, src, dst, f"Len={udp_layer.len}"

        if packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            return "ICMP", "", "", src, dst, f"Type={icmp_layer.type} Code={icmp_layer.code}"

        return "OTHER", "", "", src, dst, ""

    def _peek_http(self, packet):
        if not packet.haslayer(Raw):
            return ""
        try:
            data = packet[Raw].load.decode("utf-8", errors="replace")
        except Exception:
            return ""
        first_line = data.split("\r\n", 1)[0].strip()
        return first_line[:80] if first_line else ""

    def process_packet(self, packet):
        classified = self._classify(packet)
        if classified is None:
            return

        proto, sport, dport, src, dst, info = classified

        self.packet_count += 1
        num = self.packet_count
        timestamp = datetime.now().strftime("%H:%M:%S")

        self.stats["Total"] += 1
        self.stats[proto] = self.stats.get(proto, 0) + 1
        if proto not in self.stats:
            self.stats["Other"] += 1

        row = (num, timestamp, src, dst, proto, sport, dport, info)

        details = (
            f"=== PACKET #{num} INFO ===\n"
            f"Capture time     : {timestamp}\n"
            f"Total length     : {len(packet)} bytes\n\n"
            f"[ PROTOCOL: {proto} ]\n"
            f"  Source         : {src}\n"
            f"  Destination    : {dst}\n"
        )
        if sport:
            details += f"  Source Port    : {sport}\n  Dest Port      : {dport}\n"

        if proto == "TCP" and packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            details += f"  Seq Number     : {tcp_layer.seq}\n  Ack Number     : {tcp_layer.ack}\n  Flags          : {tcp_layer.flags}\n"
        elif proto == "DNS" and packet.haslayer(DNS):
            dns = packet[DNS]
            details += f"  Transaction ID : {dns.id}\n  {info}\n"
        elif proto == "HTTP":
            details += f"  {info}\n" if info else "  (No readable HTTP headers in this packet)\n"
        elif proto == "HTTPS":
            details += "  Payload is TLS-encrypted, contents not readable.\n"
        elif proto == "ARP":
            details += f"  {info}\n"
        elif proto == "ICMP" and packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            details += f"  Type           : {icmp_layer.type}\n  Code           : {icmp_layer.code}\n"
        elif proto == "UDP" and packet.haslayer(UDP):
            details += f"  UDP Length     : {packet[UDP].len}\n"
        else:
            details += "  Non-standard protocol, not decoded.\n"

        raw_payload = b""
        if packet.haslayer(Raw):
            raw_payload = packet[Raw].load

        self.packets_data[num] = (details, raw_payload)
        self.raw_packets.append(packet)
        self.all_rows.append(row)

        query = self.search_var.get()
        visible = self._packet_matches_query(row, query)
        self.after(0, lambda: self.insert_row_and_update_stats(row, proto, visible=visible))

    def insert_row_and_update_stats(self, row, proto, visible=True):
        if visible:
            tag = proto if proto in self.tree_tags() else "OTHER"
            self.tree.insert("", tk.END, values=row, tags=(tag,))
            self.tree.yview_moveto(1)

        for key in STAT_KEYS:
            self.stat_cards[key].configure(text=str(self.stats.get(key, 0)))

        self.count_label.configure(text=f"Packets: {self.stats['Total']}")
        self._update_search_status_label()

    def tree_tags(self):
        return {"TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "OTHER"}

    def on_row_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        item = self.tree.item(selected[0])
        try:
            num = int(item["values"][0])
        except (ValueError, IndexError):
            return

        if num in self.packets_data:
            details, _ = self.packets_data[num]

            self.info_text.configure(state="normal")
            self.info_text.delete("0.0", tk.END)
            self.info_text.insert("0.0", details)
            self.info_text.configure(state="disabled")

            self.update_payload_view()

    def show_packet_details(self, event):
        self.on_row_select(event)
        self.details_tab.set("📝 Payload")

    # ------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------
    def export_csv(self):
        if not self.all_rows:
            messagebox.showinfo("CSV Report", "No packets captured to export.")
            return

        filepath = ask_save_file(
            self,
            title="CSV Report",
            initialfile="capture_sniffer.csv",
            filetypes=[("CSV file", "*.csv")],
        )
        if not filepath:
            return

        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["No.", "Time", "Source IP", "Destination IP", "Protocol", "Src Port", "Dst Port", "Info"])
                writer.writerows(self.all_rows)
            messagebox.showinfo("CSV Report", f"Successfully exported to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_pcap(self):
        if not self.raw_packets:
            messagebox.showinfo("PCAP Capture", "No packets captured to export.")
            return

        filepath = ask_save_file(
            self,
            title="PCAP Capture",
            initialfile="capture_sniffer.pcap",
            filetypes=[("PCAP file", "*.pcap")],
        )
        if not filepath:
            return

        try:
            wrpcap(filepath, self.raw_packets)
            messagebox.showinfo("PCAP Capture", f"Successfully exported to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


def main():
    app = ModernNetworkSnifferGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
