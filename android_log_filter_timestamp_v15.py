#!/usr/bin/env python3
"""Android Log Filter for Windows with safe TkDND file dropping."""

import os
import queue
import re
import shutil
import subprocess
import threading
import faulthandler
import logging
import sys
import tempfile
import tkinter as tk
from pathlib import Path
from tkinter import colorchooser, filedialog, messagebox, ttk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    AppTkBase = TkinterDnD.Tk
    TKDND_AVAILABLE = True
except ImportError:
    DND_FILES = None
    AppTkBase = tk.Tk
    TKDND_AVAILABLE = False

MAX_TOTAL_LOG_BYTES = 100 * 1024 * 1024


def get_crash_log_path():
    base = os.environ.get("LOCALAPPDATA")
    candidates = []
    if base:
        candidates.append(Path(base) / "AndroidLogFilter")
    candidates.append(Path(tempfile.gettempdir()) / "AndroidLogFilter")
    for folder in candidates:
        try:
            folder.mkdir(parents=True, exist_ok=True)
            return folder / "android_log_filter_crash.log"
        except OSError:
            continue
    return Path("android_log_filter_crash.log").resolve()


CRASH_LOG_PATH = get_crash_log_path()
logging.basicConfig(
    filename=str(CRASH_LOG_PATH),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(threadName)s %(message)s",
    encoding="utf-8",
)
LOGGER = logging.getLogger("AndroidLogFilter")
try:
    _FAULT_LOG_HANDLE = open(CRASH_LOG_PATH, "a", encoding="utf-8", buffering=1)
    faulthandler.enable(file=_FAULT_LOG_HANDLE, all_threads=True)
except OSError:
    _FAULT_LOG_HANDLE = None


def log_unhandled_exception(exc_type, exc_value, exc_traceback, context="Unhandled exception"):
    LOGGER.critical(context, exc_info=(exc_type, exc_value, exc_traceback))


def install_global_exception_hooks():
    sys.excepthook = log_unhandled_exception
    if hasattr(threading, "excepthook"):
        def thread_hook(args):
            log_unhandled_exception(
                args.exc_type,
                args.exc_value,
                args.exc_traceback,
                f"Unhandled thread exception in {args.thread.name}",
            )
        threading.excepthook = thread_hook

LOGCAT_RE = re.compile(
    r"^(?:(?P<date>\d{2}-\d{2})\s+)?"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
    r"(?P<level>[VDIWEF])\s+(?P<tag>[^:]+?)\s*:\s(?P<message>.*)$"
)

GENERIC_TIME_RE = re.compile(
    r"(?:(?P<date>\d{2}-\d{2})\s+)?"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
)

TOKEN_RE = re.compile(
    r'\s*(?:(?P<op>AND\b|OR\b|NOT\b|&|\|)|(?P<lpar>\()|(?P<rpar>\))|'
    r'"(?P<quoted>(?:\\.|[^"])*)"|(?P<term>[^\s()&|]+))',
    re.IGNORECASE,
)


def is_probably_text_file(path, sample_size=65536):
    """Accept text logs regardless of their filename extension."""
    with open(path, "rb") as handle:
        sample = handle.read(sample_size)
    if not sample:
        return True
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True
    return b"\x00" not in sample


def read_text_log(path):
    """Read UTF-8/UTF-16 logs safely, replacing isolated bad characters."""
    with open(path, "rb") as handle:
        bom = handle.read(4)
    encoding = "utf-16" if bom.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    with open(path, "r", encoding=encoding, errors="replace") as handle:
        return handle.readlines()


def parse_logcat_line(line):
    match = LOGCAT_RE.match(line.rstrip("\r\n"))
    return match.groupdict() if match else None


def split_terms(text):
    return [item.strip() for item in re.split(r"[;,]", text) if item.strip()]


def time_to_seconds(value):
    parts = value.split(":")
    if len(parts) == 2:
        hour, minute, second = int(parts[0]), int(parts[1]), 0.0
    elif len(parts) == 3:
        hour, minute, second = int(parts[0]), int(parts[1]), float(parts[2])
    else:
        raise ValueError("Use HH:MM, HH:MM:SS, or HH:MM:SS.mmm")
    if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second < 60):
        raise ValueError("Invalid time value")
    return hour * 3600 + minute * 60 + second


def parse_filter_timestamp(text):
    text = text.strip()
    if not text:
        return None
    match = re.fullmatch(
        r"(?:(?P<date>\d{2}-\d{2})\s+)?"
        r"(?P<time>\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)",
        text,
    )
    if not match:
        raise ValueError("Use HH:MM[:SS.mmm] or MM-DD HH:MM:SS.mmm")
    seconds = time_to_seconds(match.group("time"))
    date = match.group("date")
    if not date:
        return ("time", seconds)
    month, day = map(int, date.split("-"))
    if not (1 <= month <= 12 and 1 <= day <= 31):
        raise ValueError("Invalid MM-DD date")
    return ("datetime", (month, day, seconds))


def single_timestamp_range(text, parsed):
    """Expand one timestamp into a precision-aware exact-match range."""
    time_part = text.strip().split()[-1]
    pieces = time_part.split(":")
    if len(pieces) == 2:
        width = 60.0
    elif "." not in pieces[2]:
        width = 1.0
    else:
        decimals = len(pieces[2].split(".", 1)[1])
        width = 10.0 ** (-decimals)

    if parsed[0] == "time":
        start = parsed[1]
        return ("time", start), ("time", start + width - 1e-9)

    month, day, seconds = parsed[1]
    return (
        ("datetime", (month, day, seconds)),
        ("datetime", (month, day, seconds + width - 1e-9)),
    )


def extract_line_timestamp(line, parsed=None):
    if parsed and parsed.get("time"):
        seconds = time_to_seconds(parsed["time"])
        date = parsed.get("date")
        if date:
            month, day = map(int, date.split("-"))
            return ("datetime", (month, day, seconds))
        return ("time", seconds)
    match = GENERIC_TIME_RE.search(line)
    if not match:
        return None
    seconds = time_to_seconds(match.group("time"))
    date = match.group("date")
    if date:
        month, day = map(int, date.split("-"))
        return ("datetime", (month, day, seconds))
    return ("time", seconds)


def tokenize_expression(text):
    # Normalize only the outside whitespace. Whitespace inside quoted phrases
    # and regex atoms remains untouched.
    text = text.strip()
    if not text:
        return []

    tokens = []
    pos = 0

    while pos < len(text):
        # TOKEN_RE begins with \s*, but a string containing only whitespace at
        # the end has no following token. Treat that as normal end-of-input.
        if not text[pos:].strip():
            break

        match = TOKEN_RE.match(text, pos)
        if not match:
            remainder = text[pos:].strip()
            if not remainder:
                break
            raise ValueError(f"Invalid expression near: {remainder[:25]!r}")

        pos = match.end()

        if match.group("op"):
            operator = match.group("op").upper()
            operator = {"&": "AND", "|": "OR"}.get(operator, operator)
            tokens.append((operator, None))
        elif match.group("lpar"):
            tokens.append(("LPAR", None))
        elif match.group("rpar"):
            tokens.append(("RPAR", None))
        elif match.group("quoted") is not None:
            value = re.sub(r'\\(["\\])', r'\1', match.group("quoted"))
            tokens.append(("TERM", value))
        elif match.group("term") is not None:
            tokens.append(("TERM", match.group("term")))

    return tokens


class ExpressionParser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.index = 0

    def peek(self):
        return self.tokens[self.index][0] if self.index < len(self.tokens) else None

    def take(self, expected=None):
        if self.index >= len(self.tokens):
            raise ValueError("Unexpected end of expression")
        token = self.tokens[self.index]
        if expected and token[0] != expected:
            raise ValueError(f"Expected {expected}, found {token[0]}")
        self.index += 1
        return token

    def parse(self):
        if not self.tokens:
            return None
        node = self.parse_or()
        if self.index != len(self.tokens):
            raise ValueError("Unexpected token in expression")
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek() == "OR":
            self.take("OR")
            node = ("OR", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while True:
            if self.peek() == "AND":
                self.take("AND")
                node = ("AND", node, self.parse_not())
            elif self.peek() in ("TERM", "LPAR", "NOT"):
                node = ("AND", node, self.parse_not())
            else:
                break
        return node

    def parse_not(self):
        if self.peek() == "NOT":
            self.take("NOT")
            return ("NOT", self.parse_not())
        return self.parse_primary()

    def parse_primary(self):
        kind = self.peek()
        if kind == "TERM":
            return ("TERM", self.take("TERM")[1])
        if kind == "LPAR":
            self.take("LPAR")
            node = self.parse_or()
            self.take("RPAR")
            return node
        raise ValueError(f"Expected term, found {kind or 'end'}")


def build_search_ast(search, regex_mode):
    if not search.strip():
        return None
    if regex_mode and not re.search(
        r"\b(?:AND|OR|NOT)\b|[&|]",
        search,
        re.IGNORECASE,
    ):
        return ("TERM", search.strip())
    return ExpressionParser(tokenize_expression(search)).parse()


def collect_positive_terms(node, negated=False):
    if node is None:
        return []
    kind = node[0]
    if kind == "TERM":
        return [] if negated else [node[1]]
    if kind == "NOT":
        return collect_positive_terms(node[1], not negated)
    return collect_positive_terms(node[1], negated) + collect_positive_terms(node[2], negated)


def collect_all_terms(node):
    if node is None:
        return []
    if node[0] == "TERM":
        return [node[1]]
    if node[0] == "NOT":
        return collect_all_terms(node[1])
    return collect_all_terms(node[1]) + collect_all_terms(node[2])


def compile_term_matcher(case_sensitive=False, regex_mode=False):
    flags = 0 if case_sensitive else re.IGNORECASE
    cache = {}

    def matcher(term, line):
        if regex_mode:
            if term not in cache:
                cache[term] = re.compile(term, flags)
            return cache[term].search(line) is not None
        return term in line if case_sensitive else term.lower() in line.lower()

    return matcher


def eval_expression(node, line, matcher):
    if node is None:
        return True
    kind = node[0]
    if kind == "TERM":
        return matcher(node[1], line)
    if kind == "NOT":
        return not eval_expression(node[1], line, matcher)
    if kind == "AND":
        return eval_expression(node[1], line, matcher) and eval_expression(node[2], line, matcher)
    if kind == "OR":
        return eval_expression(node[1], line, matcher) or eval_expression(node[2], line, matcher)
    raise ValueError(f"Unknown node: {kind}")


def timestamp_in_range(line_ts, start_ts, end_ts):
    if start_ts is None and end_ts is None:
        return True
    if line_ts is None:
        return False

    if (start_ts and start_ts[0] == "datetime") or (end_ts and end_ts[0] == "datetime"):
        if line_ts[0] != "datetime":
            return False
        if start_ts and start_ts[0] != "datetime":
            raise ValueError("From/To must both include MM-DD or both omit it")
        if end_ts and end_ts[0] != "datetime":
            raise ValueError("From/To must both include MM-DD or both omit it")
        value = line_ts[1]
        return (start_ts is None or value >= start_ts[1]) and (end_ts is None or value <= end_ts[1])

    seconds = line_ts[1][2] if line_ts[0] == "datetime" else line_ts[1]
    start = start_ts[1] if start_ts else None
    end = end_ts[1] if end_ts else None
    if start is not None and end is not None and start > end:
        return seconds >= start or seconds <= end
    return (start is None or seconds >= start) and (end is None or seconds <= end)



class AndroidLogFilterApp(AppTkBase):
    CATEGORY_NAMES = {
        "V": "Verbose",
        "D": "Debug",
        "I": "Info",
        "W": "Warning",
        "E": "Error",
        "F": "Fatal",
        "OTHER": "Other",
    }

    def __init__(self):
        super().__init__()
        self.title("Android Log Filter v15")
        self.geometry("1450x950")
        self.minsize(1100, 720)

        self.source_lines = []
        self.filtered_lines = []
        self.filtered_items = []  # [(source_index, line)]

        self.adb_process = None
        self.adb_thread = None
        self.adb_queue = queue.Queue()
        self.adb_running = False

        self.highlight_color = "#fff59d"
        self.mark_color = "#ffb3b3"
        self.manual_marks = {}  # source_index -> selected color
        self.selected_source_index = None

        self.category_visible = {
            "V": True,
            "D": True,
            "I": True,
            "W": True,
            "E": True,
            "F": True,
            "OTHER": True,
        }
        self.category_buttons = {}

        # Collapsible filter sections.
        # Default UI: Search is the only visible/enabled filter section.
        self.section_names = {
            "search": "Search",
            "terms": "Include / Exclude",
            "identity": "Level / Tag / PID",
            "time": "Time",
            "appearance": "Colors / Marks",
            "quick": "Quick Filters",
            "categories": "Categories",
        }
        self.section_visible = {
            "search": True,
            "terms": False,
            "identity": False,
            "time": False,
            "appearance": False,
            "quick": False,
            "categories": False,
        }
        self.section_frames = {}
        self.section_buttons = {}

        self._drop_enabled = False

        self._build_ui()
        self.after(100, self._drain_adb_queue)
        self.after(250, self._enable_windows_file_drop)

    def report_callback_exception(self, exc_type, exc_value, exc_traceback):
        """Capture every Tkinter callback failure instead of failing silently."""
        log_unhandled_exception(exc_type, exc_value, exc_traceback, "Tkinter callback failed")
        try:
            messagebox.showerror(
                "Android Log Filter error",
                f"The operation could not be completed.\n\n"
                f"Crash details were saved to:\n{CRASH_LOG_PATH}",
            )
            self.status_var.set(f"Error saved to: {CRASH_LOG_PATH}")
        except Exception:
            pass

    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill=tk.X)

        ttk.Button(top, text="Open Log File", command=self.open_file).pack(side=tk.LEFT, padx=(0, 6))

        self.drop_target = tk.Label(
            top,
            text="Drop any text log here",
            relief=tk.GROOVE,
            bd=2,
            padx=18,
            pady=6,
            cursor="hand2",
        )
        self.drop_target.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(top, text="Save Filtered", command=self.save_filtered).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Clear", command=self.clear_all).pack(side=tk.LEFT, padx=6)

        ttk.Separator(top, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        self.adb_start_btn = ttk.Button(top, text="Start ADB Logcat", command=self.start_adb)
        self.adb_start_btn.pack(side=tk.LEFT, padx=6)

        self.adb_stop_btn = ttk.Button(top, text="Stop ADB", command=self.stop_adb, state=tk.DISABLED)
        self.adb_stop_btn.pack(side=tk.LEFT, padx=6)

        filter_box = ttk.LabelFrame(self, text="Filters", padding=8)
        filter_box.pack(fill=tk.X, padx=8, pady=(0, 6))
        filter_box.columnconfigure(0, weight=1)

        # Always-visible section selector.
        selector = ttk.Frame(filter_box)
        selector.grid(row=0, column=0, sticky="ew", pady=(0, 5))

        ttk.Label(selector, text="Filter sections:").pack(side=tk.LEFT, padx=(0, 6))

        for key in ("search", "terms", "identity", "time", "appearance", "quick", "categories"):
            button = ttk.Button(
                selector,
                width=17,
                command=lambda section=key: self.toggle_filter_section(section),
            )
            button.pack(side=tk.LEFT, padx=2)
            self.section_buttons[key] = button

        ttk.Button(
            selector,
            text="Search Only",
            command=self.reset_filter_sections,
        ).pack(side=tk.RIGHT, padx=(6, 0))

        # Search.
        row1 = ttk.Frame(filter_box)
        row1.grid(row=1, column=0, sticky="ew", pady=3)
        self.section_frames["search"] = row1

        ttk.Label(row1, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(row1, textvariable=self.search_var, width=58)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 12))
        search_entry.bind("<Return>", lambda _e: self.apply_filter())

        self.regex_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row1, text="Regex", variable=self.regex_var).pack(side=tk.LEFT, padx=4)

        self.case_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row1, text="Case sensitive", variable=self.case_var).pack(side=tk.LEFT, padx=4)

        ttk.Button(row1, text="Apply", command=self.apply_filter).pack(side=tk.LEFT, padx=(8, 4))
        ttk.Button(
            row1,
            text="Hide",
            width=7,
            command=lambda: self.set_filter_section_visible("search", False),
        ).pack(side=tk.RIGHT)

        # Include / Exclude.
        row2 = ttk.Frame(filter_box)
        row2.grid(row=2, column=0, sticky="ew", pady=3)
        self.section_frames["terms"] = row2

        ttk.Label(row2, text="Include terms:").pack(side=tk.LEFT)
        self.include_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.include_var, width=32).pack(side=tk.LEFT, padx=(5, 5))

        self.include_mode_var = tk.StringVar(value="ALL")
        ttk.Combobox(
            row2,
            textvariable=self.include_mode_var,
            values=["ALL", "ANY"],
            state="readonly",
            width=5,
        ).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(row2, text="Exclude terms:").pack(side=tk.LEFT)
        self.exclude_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.exclude_var, width=32).pack(side=tk.LEFT, padx=(5, 10))
        ttk.Label(row2, text="comma/semicolon separated").pack(side=tk.LEFT)

        ttk.Button(
            row2,
            text="Hide",
            width=7,
            command=lambda: self.set_filter_section_visible("terms", False),
        ).pack(side=tk.RIGHT)

        # Level / Tag / PID.
        row3 = ttk.Frame(filter_box)
        row3.grid(row=3, column=0, sticky="ew", pady=3)
        self.section_frames["identity"] = row3

        ttk.Label(row3, text="Level:").pack(side=tk.LEFT)
        self.level_var = tk.StringVar(value="ALL")
        ttk.Combobox(
            row3,
            textvariable=self.level_var,
            values=["ALL", "V", "D", "I", "W", "E", "F"],
            width=6,
            state="readonly",
        ).pack(side=tk.LEFT, padx=(5, 12))

        ttk.Label(row3, text="Tag contains:").pack(side=tk.LEFT)
        self.tag_var = tk.StringVar()
        ttk.Entry(row3, textvariable=self.tag_var, width=22).pack(side=tk.LEFT, padx=(5, 12))

        ttk.Label(row3, text="PID:").pack(side=tk.LEFT)
        self.pid_var = tk.StringVar()
        ttk.Entry(row3, textvariable=self.pid_var, width=10).pack(side=tk.LEFT, padx=(5, 12))

        self.parsed_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            row3,
            text="Only parsed logcat lines",
            variable=self.parsed_only_var,
        ).pack(side=tk.LEFT)

        ttk.Button(
            row3,
            text="Hide",
            width=7,
            command=lambda: self.set_filter_section_visible("identity", False),
        ).pack(side=tk.RIGHT)

        # Time.
        row4 = ttk.Frame(filter_box)
        row4.grid(row=4, column=0, sticky="ew", pady=3)
        self.section_frames["time"] = row4

        ttk.Label(row4, text="From time:").pack(side=tk.LEFT)
        self.from_time_var = tk.StringVar()
        ttk.Entry(row4, textvariable=self.from_time_var, width=19).pack(side=tk.LEFT, padx=(5, 12))

        ttk.Label(row4, text="To time:").pack(side=tk.LEFT)
        self.to_time_var = tk.StringVar()
        ttk.Entry(row4, textvariable=self.to_time_var, width=19).pack(side=tk.LEFT, padx=(5, 12))

        ttk.Button(row4, text="Clear Time", command=self.clear_time_filter).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(
            row4,
            text=(
                "One field = exact time; both fields = range. "
                "HH:MM[:SS.mmm] or MM-DD HH:MM:SS.mmm"
            ),
        ).pack(side=tk.LEFT)

        ttk.Button(
            row4,
            text="Hide",
            width=7,
            command=lambda: self.set_filter_section_visible("time", False),
        ).pack(side=tk.RIGHT)

        # Colors / Marks.
        row5 = ttk.Frame(filter_box)
        row5.grid(row=5, column=0, sticky="ew", pady=3)
        self.section_frames["appearance"] = row5

        self.highlight_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row5, text="Highlight matches", variable=self.highlight_var).pack(side=tk.LEFT)

        self.color_button = tk.Button(
            row5,
            text="Match Color",
            command=self.select_highlight_color,
            bg=self.highlight_color,
            padx=8,
        )
        self.color_button.pack(side=tk.LEFT, padx=(8, 12))

        self.mark_color_button = tk.Button(
            row5,
            text="Mark Color",
            command=self.select_mark_color,
            bg=self.mark_color,
            padx=8,
        )
        self.mark_color_button.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(row5, text="Clear Marks", command=self.clear_marks).pack(side=tk.LEFT, padx=(0, 16))
        ttk.Label(
            row5,
            text='Boolean: AND or & / OR or | / NOT / ( ) / "quoted phrase"',
        ).pack(side=tk.LEFT)

        ttk.Button(
            row5,
            text="Hide",
            width=7,
            command=lambda: self.set_filter_section_visible("appearance", False),
        ).pack(side=tk.RIGHT)

        # Quick filters.
        row6 = ttk.Frame(filter_box)
        row6.grid(row=6, column=0, sticky="ew", pady=3)
        self.section_frames["quick"] = row6

        ttk.Label(row6, text="Quick filters:").pack(side=tk.LEFT)
        ttk.Button(row6, text="Errors", command=lambda: self.quick_level("E")).pack(side=tk.LEFT, padx=4)
        ttk.Button(row6, text="Warnings", command=lambda: self.quick_level("W")).pack(side=tk.LEFT, padx=4)
        ttk.Button(row6, text="ANR", command=lambda: self.quick_search("ANR")).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            row6,
            text="Crash/Fatal",
            command=lambda: self.quick_search(r"FATAL EXCEPTION|Fatal signal|AndroidRuntime", True),
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            row6,
            text="Network/DNS",
            command=lambda: self.quick_search(r"DNS|UnknownHost|HTTP|HTTPS|Socket|Connectivity", True),
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            row6,
            text="Binder",
            command=lambda: self.quick_search(r"Binder|binder", True),
        ).pack(side=tk.LEFT, padx=4)

        ttk.Button(
            row6,
            text="Hide",
            width=7,
            command=lambda: self.set_filter_section_visible("quick", False),
        ).pack(side=tk.RIGHT)

        # Categories.
        category_box = ttk.Frame(filter_box)
        category_box.grid(row=7, column=0, sticky="ew", pady=3)
        self.section_frames["categories"] = category_box

        ttk.Label(category_box, text="Categories:").pack(side=tk.LEFT, padx=(0, 8))

        for key in ("V", "D", "I", "W", "E", "F", "OTHER"):
            item = ttk.Frame(category_box, padding=(3, 0))
            item.pack(side=tk.LEFT, padx=3)

            ttk.Label(
                item,
                text=f"{key if key != 'OTHER' else '-'} {self.CATEGORY_NAMES[key]}",
            ).pack(side=tk.LEFT)

            button = ttk.Button(
                item,
                text="Hide",
                width=6,
                command=lambda category=key: self.toggle_category(category),
            )
            button.pack(side=tk.LEFT, padx=(4, 0))
            self.category_buttons[key] = button

        ttk.Button(category_box, text="Show All", command=self.show_all_categories).pack(side=tk.LEFT, padx=(8, 3))
        ttk.Button(category_box, text="Hide All", command=self.hide_all_categories).pack(side=tk.LEFT, padx=3)

        ttk.Button(
            category_box,
            text="Hide",
            width=7,
            command=lambda: self.set_filter_section_visible("categories", False),
        ).pack(side=tk.RIGHT)

        # Requested startup state: Search only.
        self._apply_filter_section_visibility()

        # Log panes.
        paned = ttk.Panedwindow(self, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        source_frame = ttk.LabelFrame(
            paned,
            text="Source Log — DROP ANY TEXT LOG HERE — select any text and Ctrl+C",
        )
        result_frame = ttk.LabelFrame(
            paned,
            text="Filtered Result — click a line to show it above; Ctrl+Click to mark",
        )
        paned.add(source_frame, weight=1)
        paned.add(result_frame, weight=1)

        self.source_text = self._make_text_area(source_frame)
        self.result_text = self._make_text_area(result_frame)

        self.source_text.bind("<Button-1>", self._on_source_click)
        self.result_text.bind("<Button-1>", self._on_result_click)
        self.source_text.bind("<Control-Button-1>", self._on_source_mark_click)
        self.result_text.bind("<Control-Button-1>", self._on_result_mark_click)
        for widget in (self.source_text, self.result_text):
            widget.bind("<Button-3>", self._show_text_context_menu)
            widget.bind("<Control-c>", self._copy_selected_text)
            widget.bind("<Control-C>", self._copy_selected_text)
        self.result_text.tag_configure("match_highlight", background=self.highlight_color)
        self.source_text.tag_configure("selected_source_line", background="#CFE8FF")

        self.text_context_menu = tk.Menu(self, tearoff=False)
        self.text_context_menu.add_command(label="Copy", command=self._copy_context_selection)
        self.text_context_menu.add_command(label="Copy Line", command=self._copy_context_line)
        self.text_context_menu.add_separator()
        self.text_context_menu.add_command(label="Select All", command=self._select_all_context)
        self._context_widget = None

        status = ttk.Frame(self, padding=(8, 0, 8, 8))
        status.pack(fill=tk.X)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status, textvariable=self.status_var).pack(side=tk.LEFT)

        self.count_var = tk.StringVar(value="0 lines")
        ttk.Label(status, textvariable=self.count_var).pack(side=tk.RIGHT)

    def _make_text_area(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True)

        yscroll = ttk.Scrollbar(frame, orient=tk.VERTICAL)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)

        xscroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)

        text = tk.Text(
            frame,
            wrap=tk.NONE,
            yscrollcommand=yscroll.set,
            xscrollcommand=xscroll.set,
            font=("Consolas", 10),
            undo=False,
        )
        text.pack(fill=tk.BOTH, expand=True)

        yscroll.config(command=text.yview)
        xscroll.config(command=text.xview)
        return text

    # ---------- Collapsible filter sections ----------
    def toggle_filter_section(self, section):
        self.set_filter_section_visible(section, not self.section_visible[section])

    def set_filter_section_visible(self, section, visible):
        self.section_visible[section] = bool(visible)

        frame = self.section_frames.get(section)
        if frame is not None:
            if visible:
                frame.grid()
            else:
                frame.grid_remove()

        self._refresh_section_button(section)

        # Hidden filter sections are disabled immediately. Their values are
        # retained so the user can restore them by showing the section again.
        if hasattr(self, "result_text"):
            self.apply_filter()

    def _refresh_section_button(self, section):
        button = self.section_buttons.get(section)
        if button is None:
            return
        action = "Hide" if self.section_visible[section] else "Show"
        button.configure(text=f"{self.section_names[section]}: {action}")

    def _apply_filter_section_visibility(self):
        for section, visible in self.section_visible.items():
            frame = self.section_frames.get(section)
            if frame is not None:
                if visible:
                    frame.grid()
                else:
                    frame.grid_remove()
            self._refresh_section_button(section)

    def reset_filter_sections(self):
        for section in self.section_visible:
            self.section_visible[section] = (section == "search")
        self._apply_filter_section_visibility()
        if hasattr(self, "result_text"):
            self.apply_filter()

    # ---------- Category visibility ----------
    def toggle_category(self, category):
        self.category_visible[category] = not self.category_visible[category]
        self._refresh_category_button(category)
        self.apply_filter()

    def _refresh_category_button(self, category):
        button = self.category_buttons.get(category)
        if button is not None:
            button.configure(text="Hide" if self.category_visible[category] else "Show")

    def show_all_categories(self):
        for category in self.category_visible:
            self.category_visible[category] = True
            self._refresh_category_button(category)
        self.apply_filter()

    def hide_all_categories(self):
        for category in self.category_visible:
            self.category_visible[category] = False
            self._refresh_category_button(category)
        self.apply_filter()

    def _line_category(self, parsed):
        if parsed is None:
            return "OTHER"
        level = parsed.get("level")
        return level if level in ("V", "D", "I", "W", "E", "F") else "OTHER"

    # ---------- Safe Tk drag & drop ----------
    def _enable_windows_file_drop(self):
        """Enable drag/drop through TkDND without replacing a Windows WndProc."""
        if self._drop_enabled:
            return

        if not TKDND_AVAILABLE:
            self.drop_target.configure(text="Drag/drop setup required")
            self.status_var.set(
                "Drag/drop unavailable — install tkinterdnd2 or use Open Log File"
            )
            LOGGER.warning("tkinterdnd2 is not installed; drag/drop is disabled")
            return

        try:
            targets = (
                (self.drop_target, "drop-area"),
                (self.source_text, "source"),
                (self, "window"),
            )
            for widget, target_name in targets:
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind(
                    "<<Drop>>",
                    lambda event, target=target_name:
                        self._on_tkdnd_drop(event, target),
                )

            self._drop_enabled = True
            self.drop_target.configure(text="Drop here or into Source Log")
            self.status_var.set(
                "Ready — drag any text log into Source Log or use Open Log File"
            )
            LOGGER.info("Safe TkDND drag/drop enabled")
        except Exception as exc:
            LOGGER.exception("TkDND initialization failed")
            self._drop_enabled = False
            self.drop_target.configure(text="Drag/drop unavailable")
            self.status_var.set(f"Drag/drop unavailable: {exc}")

    def _on_tkdnd_drop(self, event, target):
        """Parse TkDND's brace-safe Windows path list and load the files."""
        try:
            paths = list(self.tk.splitlist(event.data))
            if paths:
                self._handle_dropped_files(paths, target)
        except BaseException as exc:
            LOGGER.exception("TkDND drop failed: %r", getattr(event, "data", None))
            messagebox.showerror(
                "Could not load dropped log",
                f"The dropped file could not be processed.\n\n"
                f"Diagnostic log:\n{CRASH_LOG_PATH}\n\nError: {exc}",
            )
        return getattr(event, "action", None)

    def _handle_dropped_files(self, paths, target="window"):
        # Rotated Android logs often end in .1, .14, etc. Validate content
        # instead of rejecting a file based on its final suffix.
        try:
            self.load_log_paths(paths, drop_target=target)
        except BaseException as exc:
            LOGGER.exception("Dropped-file operation failed: %r", paths)
            try:
                messagebox.showerror(
                    "Could not load dropped log",
                    f"The file could not be loaded. The app will remain open.\n\n"
                    f"Crash details were saved to:\n{CRASH_LOG_PATH}\n\n"
                    f"Error: {exc}",
                )
            except Exception:
                pass

    # ---------- File ----------
    def open_file(self):
        paths = filedialog.askopenfilenames(
            title="Open Android log",
            filetypes=[
                ("All log/text files", "*.*"),
                ("Common logs", "*.log *.txt *.out *.trace *.dump"),
                ("Text files", "*.txt"),
                ("Log files", "*.log"),
            ],
        )
        if not paths:
            return
        self.load_log_paths(list(paths))

    def load_log_paths(self, paths, drop_target=None):
        """Load one or more dropped/selected log files in the given order."""
        LOGGER.info("Loading %d file(s): %r", len(paths), [str(p) for p in paths])
        valid_paths = []
        rejected_names = []
        total_bytes = 0
        for path in paths:
            p = Path(path)
            try:
                if p.is_file() and is_probably_text_file(p):
                    valid_paths.append(p)
                    total_bytes += p.stat().st_size
                else:
                    rejected_names.append(p.name)
            except OSError:
                LOGGER.exception("Could not inspect log file: %s", p)
                rejected_names.append(p.name)

        if not valid_paths:
            messagebox.showwarning(
                "No valid log file",
                "No readable text log was found. Rotated names such as .log.14 "
                "are supported; binary files are not.",
            )
            return

        if total_bytes > MAX_TOTAL_LOG_BYTES:
            LOGGER.warning(
                "Rejected oversized log selection: %d bytes across %d files",
                total_bytes,
                len(valid_paths),
            )
            messagebox.showwarning(
                "Log is too large",
                f"The selected text log is {total_bytes / (1024 * 1024):,.1f} MB.\n\n"
                f"For stability, this version loads at most "
                f"{MAX_TOTAL_LOG_BYTES / (1024 * 1024):,.0f} MB at once.\n"
                f"The application has not loaded the file.\n\n"
                f"Diagnostic log:\n{CRASH_LOG_PATH}",
            )
            return

        lines = []
        loaded_names = []

        try:
            for p in valid_paths:
                file_lines = read_text_log(p)

                if len(valid_paths) > 1:
                    separator = (
                        f"\\n===== FILE: {p.name} =====\\n"
                    )
                    lines.append(separator)

                lines.extend(file_lines)
                loaded_names.append(p.name)
        except (OSError, UnicodeError, MemoryError) as exc:
            LOGGER.exception("Reading log file failed")
            messagebox.showerror(
                "Open failed",
                f"{exc}\n\nDiagnostic log:\n{CRASH_LOG_PATH}",
            )
            return

        try:
            self.source_lines = lines
            self.manual_marks.clear()
            self.selected_source_index = None
            self._render_source()
            self.apply_filter()
        except (tk.TclError, MemoryError) as exc:
            LOGGER.exception("Rendering log file failed")
            self.source_lines.clear()
            self.filtered_lines.clear()
            self.filtered_items.clear()
            try:
                self.source_text.delete("1.0", tk.END)
                self.result_text.delete("1.0", tk.END)
            except tk.TclError:
                pass
            messagebox.showerror(
                "Log rendering failed",
                f"The file was too large or could not be rendered.\n\n"
                f"Diagnostic log:\n{CRASH_LOG_PATH}\n\nError: {exc}",
            )
            return

        LOGGER.info(
            "Loaded %d file(s), %d bytes, %d lines",
            len(valid_paths),
            total_bytes,
            len(lines),
        )

        if len(loaded_names) == 1:
            self.status_var.set(f"Loaded: {valid_paths[0]}")
            if hasattr(self, "drop_target"):
                self.drop_target.configure(text=f"Loaded: {loaded_names[0]}")
        else:
            self.status_var.set(
                f"Loaded {len(loaded_names)} files: " + ", ".join(loaded_names)
            )
            if hasattr(self, "drop_target"):
                self.drop_target.configure(
                    text=f"Loaded {len(loaded_names)} log files"
                )

        if rejected_names:
            where = "Source Log" if drop_target == "source" else "application"
            self.status_var.set(
                f"Loaded {len(loaded_names)} text log(s) into {where}; ignored "
                f"{len(rejected_names)} missing/binary file(s)."
            )

    def save_filtered(self):
        if not self.filtered_lines:
            messagebox.showinfo("Nothing to save", "There is no filtered output.")
            return

        path = filedialog.asksaveasfilename(
            title="Save filtered log",
            defaultextension=".log",
            filetypes=[("Log file", "*.log"), ("Text file", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.writelines(self.filtered_lines)
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))
            return

        self.status_var.set(f"Saved: {path}")

    def clear_all(self):
        self.stop_adb()
        self.source_lines.clear()
        self.filtered_lines.clear()
        self.filtered_items.clear()
        self.manual_marks.clear()
        self.selected_source_index = None

        self.source_text.delete("1.0", tk.END)
        self.result_text.delete("1.0", tk.END)

        for var in (
            self.search_var,
            self.include_var,
            self.exclude_var,
            self.tag_var,
            self.pid_var,
            self.from_time_var,
            self.to_time_var,
        ):
            var.set("")

        self.level_var.set("ALL")

        for category in self.category_visible:
            self.category_visible[category] = True
            self._refresh_category_button(category)

        self.reset_filter_sections()
        self.status_var.set("Ready")
        self.count_var.set("0 lines")
        if hasattr(self, "drop_target"):
            self.drop_target.configure(text="Drop any text log here")

    # ---------- Time / search ----------
    def clear_time_filter(self):
        self.from_time_var.set("")
        self.to_time_var.set("")
        self.apply_filter()

    def select_highlight_color(self):
        _rgb, color = colorchooser.askcolor(
            color=self.highlight_color,
            title="Select match highlight color",
        )
        if not color:
            return
        self.highlight_color = color
        self.color_button.configure(bg=color)
        self.result_text.tag_configure("match_highlight", background=color)
        self.apply_filter()

    def select_mark_color(self):
        _rgb, color = colorchooser.askcolor(
            color=self.mark_color,
            title="Select manual line mark color",
        )
        if not color:
            return
        self.mark_color = color
        self.mark_color_button.configure(bg=color)

    def quick_level(self, level):
        self.level_var.set(level)
        self.set_filter_section_visible("identity", True)

    def quick_search(self, text, regex=False):
        self.search_var.set(text)
        self.regex_var.set(regex)
        self.set_filter_section_visible("search", True)

    def _validate_filters(self):
        if self.section_visible["time"]:
            from_text = self.from_time_var.get()
            to_text = self.to_time_var.get()
            start_ts = parse_filter_timestamp(from_text)
            end_ts = parse_filter_timestamp(to_text)

            if (start_ts is None) != (end_ts is None):
                entered_text = from_text if start_ts is not None else to_text
                entered_ts = start_ts if start_ts is not None else end_ts
                start_ts, end_ts = single_timestamp_range(entered_text, entered_ts)
        else:
            start_ts = None
            end_ts = None

        if start_ts and end_ts and start_ts[0] != end_ts[0]:
            raise ValueError("From and To must both include MM-DD or both use time only")

        ast = (
            build_search_ast(self.search_var.get(), self.regex_var.get())
            if self.section_visible["search"]
            else None
        )
        matcher = compile_term_matcher(self.case_var.get(), self.regex_var.get())

        if self.regex_var.get() and ast:
            for term in collect_all_terms(ast):
                matcher(term, "")

        return start_ts, end_ts, ast, matcher

    def apply_filter(self):
        try:
            start_ts, end_ts, search_ast, matcher = self._validate_filters()
        except (ValueError, re.error) as exc:
            messagebox.showerror("Invalid filter", str(exc))
            return

        if self.section_visible["terms"]:
            include_terms = split_terms(self.include_var.get())
            exclude_terms = split_terms(self.exclude_var.get())
            include_mode = self.include_mode_var.get()
        else:
            include_terms = []
            exclude_terms = []
            include_mode = "ALL"

        if self.section_visible["identity"]:
            level = self.level_var.get()
            tag = self.tag_var.get().strip()
            pid = self.pid_var.get().strip()
            parsed_only = self.parsed_only_var.get()
        else:
            level = "ALL"
            tag = ""
            pid = ""
            parsed_only = False

        case_sensitive = self.case_var.get()

        contains = (
            (lambda haystack, needle: needle in haystack)
            if case_sensitive
            else (lambda haystack, needle: needle.lower() in haystack.lower())
        )

        result_items = []

        for source_index, line in enumerate(self.source_lines):
            parsed = parse_logcat_line(line)
            category = self._line_category(parsed)

            # Category filtering is disabled while the Categories section
            # itself is hidden.
            if (
                self.section_visible["categories"]
                and not self.category_visible.get(category, True)
            ):
                continue

            if parsed_only and parsed is None:
                continue

            if level != "ALL" and (parsed is None or parsed.get("level") != level):
                continue

            if tag and (parsed is None or not contains(parsed.get("tag", ""), tag)):
                continue

            if pid and (parsed is None or parsed.get("pid") != pid):
                continue

            if start_ts is not None or end_ts is not None:
                if not timestamp_in_range(extract_line_timestamp(line, parsed), start_ts, end_ts):
                    continue

            if search_ast is not None and not eval_expression(search_ast, line, matcher):
                continue

            if include_terms:
                checks = [contains(line, term) for term in include_terms]
                if include_mode == "ANY" and not any(checks):
                    continue
                if include_mode == "ALL" and not all(checks):
                    continue

            if exclude_terms and any(contains(line, term) for term in exclude_terms):
                continue

            result_items.append((source_index, line))

        self.filtered_items = result_items
        self.filtered_lines = [line for _source_index, line in result_items]
        self._render_result(search_ast, include_terms)

        hidden = (
            [
                self.CATEGORY_NAMES[key]
                for key, visible in self.category_visible.items()
                if not visible
            ]
            if self.section_visible["categories"]
            else []
        )
        hidden_text = f" | hidden categories: {', '.join(hidden)}" if hidden else ""
        self.count_var.set(
            f"{len(self.source_lines):,} source / {len(self.filtered_lines):,} filtered{hidden_text}"
        )
        self.status_var.set("Filter applied")

    # ---------- Rendering / manual marks ----------
    def _mark_tag_name(self, color):
        return "manual_" + color.lstrip("#").replace(" ", "_")

    def _configure_mark_tag(self, widget, color):
        tag = self._mark_tag_name(color)
        widget.tag_configure(tag, background=color)
        return tag

    def _render_source(self):
        self.source_text.delete("1.0", tk.END)
        self.source_text.insert("1.0", "".join(self.source_lines))
        self._apply_source_marks()
        self._apply_selected_source_line()

    def _apply_selected_source_line(self):
        self.source_text.tag_remove("selected_source_line", "1.0", tk.END)
        if self.selected_source_index is None:
            return
        if 0 <= self.selected_source_index < len(self.source_lines):
            row = self.selected_source_index + 1
            self.source_text.tag_add("selected_source_line", f"{row}.0", f"{row}.end")
            self.source_text.tag_raise("selected_source_line")

    def _show_source_line(self, source_index):
        if not (0 <= source_index < len(self.source_lines)):
            return
        self.selected_source_index = source_index
        row = source_index + 1
        self._apply_selected_source_line()
        self.source_text.mark_set(tk.INSERT, f"{row}.0")
        self.source_text.see(f"{row}.0")
        self.status_var.set(
            f"Source line {row:,} shown above — select any text and press Ctrl+C"
        )

    def _apply_source_marks(self):
        # Remove only manual tags.
        for tag in self.source_text.tag_names():
            if tag.startswith("manual_"):
                self.source_text.tag_delete(tag)

        for source_index, color in self.manual_marks.items():
            if 0 <= source_index < len(self.source_lines):
                tag = self._configure_mark_tag(self.source_text, color)
                row = source_index + 1
                self.source_text.tag_add(tag, f"{row}.0", f"{row}.end")

    def _render_result(self, search_ast, include_terms):
        self.result_text.delete("1.0", tk.END)

        # Remove old manual mark tags before creating current ones.
        for tag in self.result_text.tag_names():
            if tag.startswith("manual_"):
                self.result_text.tag_delete(tag)

        self.result_text.tag_configure("match_highlight", background=self.highlight_color)

        search_terms = collect_positive_terms(search_ast)
        items = [(term, self.regex_var.get()) for term in search_terms]
        items += [(term, False) for term in include_terms]

        unique = []
        seen = set()
        for term, is_regex in items:
            key = (term, is_regex)
            if term and key not in seen:
                seen.add(key)
                unique.append(key)

        flags = 0 if self.case_var.get() else re.IGNORECASE
        patterns = []
        if self.highlight_var.get():
            for term, is_regex in unique:
                try:
                    patterns.append(
                        re.compile(term if is_regex else re.escape(term), flags)
                    )
                except re.error:
                    pass

        for row, (source_index, line) in enumerate(self.filtered_items, start=1):
            self.result_text.insert(tk.END, line)

            if source_index in self.manual_marks:
                color = self.manual_marks[source_index]
                tag = self._configure_mark_tag(self.result_text, color)
                self.result_text.tag_add(tag, f"{row}.0", f"{row}.end")

            for pattern in patterns:
                for match in pattern.finditer(line):
                    if match.start() != match.end():
                        self.result_text.tag_add(
                            "match_highlight",
                            f"{row}.{match.start()}",
                            f"{row}.{match.end()}",
                        )

        # Keep keyword highlights visible on top of whole-line marks.
        self.result_text.tag_raise("match_highlight")

    def _toggle_mark(self, source_index):
        if not (0 <= source_index < len(self.source_lines)):
            return

        if source_index in self.manual_marks:
            del self.manual_marks[source_index]
        else:
            self.manual_marks[source_index] = self.mark_color

        self._apply_source_marks()
        self._render_result_from_current_filters()

    def _render_result_from_current_filters(self):
        # Re-render without changing the current filter result.
        try:
            _start, _end, search_ast, _matcher = self._validate_filters()
        except (ValueError, re.error):
            search_ast = None
        include_terms = (
            split_terms(self.include_var.get())
            if self.section_visible["terms"]
            else []
        )
        self._render_result(search_ast, include_terms)

    def _on_source_click(self, event):
        index = self.source_text.index(f"@{event.x},{event.y}")
        row = int(index.split(".")[0])
        self.selected_source_index = row - 1
        self.after_idle(self._apply_selected_source_line)

    def _on_result_click(self, event):
        index = self.result_text.index(f"@{event.x},{event.y}")
        row = int(index.split(".")[0])
        if 1 <= row <= len(self.filtered_items):
            source_index = self.filtered_items[row - 1][0]
            self.after_idle(lambda: self._show_source_line(source_index))

    def _on_source_mark_click(self, event):
        index = self.source_text.index(f"@{event.x},{event.y}")
        self._toggle_mark(int(index.split(".")[0]) - 1)
        return "break"

    def _on_result_mark_click(self, event):
        index = self.result_text.index(f"@{event.x},{event.y}")
        row = int(index.split(".")[0])
        if 1 <= row <= len(self.filtered_items):
            source_index = self.filtered_items[row - 1][0]
            self._show_source_line(source_index)
            self._toggle_mark(source_index)
        return "break"

    def _copy_selected_text(self, event):
        widget = event.widget
        try:
            value = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            return "break"
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status_var.set(f"Copied {len(value):,} character(s)")
        return "break"

    def _show_text_context_menu(self, event):
        self._context_widget = event.widget
        event.widget.mark_set(tk.INSERT, f"@{event.x},{event.y}")
        try:
            self.text_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.text_context_menu.grab_release()
        return "break"

    def _copy_context_selection(self):
        widget = self._context_widget
        if widget is None:
            return
        try:
            value = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            messagebox.showinfo("Copy", "Select some text first.")
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status_var.set(f"Copied {len(value):,} character(s)")

    def _copy_context_line(self):
        widget = self._context_widget
        if widget is None:
            return
        row = widget.index(tk.INSERT).split(".")[0]
        value = widget.get(f"{row}.0", f"{row}.end")
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status_var.set("Copied current line")

    def _select_all_context(self):
        widget = self._context_widget
        if widget is None:
            return
        widget.tag_add(tk.SEL, "1.0", "end-1c")
        widget.mark_set(tk.INSERT, "1.0")
        widget.focus_set()

    def clear_marks(self):
        self.manual_marks.clear()
        self._apply_source_marks()
        self._render_result_from_current_filters()

    # ---------- ADB ----------
    def find_adb(self):
        adb = shutil.which("adb")
        if adb:
            return adb

        common = [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk" / "platform-tools" / "adb.exe",
            Path(os.environ.get("ANDROID_HOME", "")) / "platform-tools" / "adb.exe",
            Path(os.environ.get("ANDROID_SDK_ROOT", "")) / "platform-tools" / "adb.exe",
        ]
        return next((str(path) for path in common if path.is_file()), None)

    def start_adb(self):
        if self.adb_running:
            return

        adb = self.find_adb()
        if not adb:
            messagebox.showerror(
                "ADB not found",
                "adb.exe was not found.\n\n"
                "Install Android SDK Platform-Tools or add platform-tools to PATH.",
            )
            return

        try:
            devices = subprocess.run(
                [adb, "devices"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            connected = [
                line
                for line in devices.stdout.splitlines()[1:]
                if line.strip().endswith("\tdevice")
            ]
            if not connected:
                messagebox.showwarning("No device", "No authorized Android device is connected.")
                return
        except Exception as exc:
            messagebox.showerror("ADB error", str(exc))
            return

        self.stop_adb()
        self.source_lines.clear()
        self.filtered_lines.clear()
        self.filtered_items.clear()
        self.manual_marks.clear()
        self.source_text.delete("1.0", tk.END)
        self.result_text.delete("1.0", tk.END)

        try:
            self.adb_process = subprocess.Popen(
                [adb, "logcat", "-v", "threadtime"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except OSError as exc:
            messagebox.showerror("ADB start failed", str(exc))
            return

        self.adb_running = True
        self.adb_start_btn.config(state=tk.DISABLED)
        self.adb_stop_btn.config(state=tk.NORMAL)
        self.status_var.set("ADB logcat running...")

        self.adb_thread = threading.Thread(target=self._read_adb, daemon=True)
        self.adb_thread.start()

    def _read_adb(self):
        process = self.adb_process
        if process is None or process.stdout is None:
            return

        try:
            for line in process.stdout:
                if not self.adb_running:
                    break
                self.adb_queue.put(line)
        finally:
            self.adb_queue.put(None)

    def _drain_adb_queue(self):
        batch = []

        try:
            while len(batch) < 500:
                item = self.adb_queue.get_nowait()
                if item is None:
                    break
                batch.append(item)
        except queue.Empty:
            pass

        if batch:
            self.source_lines.extend(batch)
            self._render_source()
            self.source_text.see(tk.END)
            self.apply_filter()
            self.result_text.see(tk.END)

        self.after(100, self._drain_adb_queue)

    def stop_adb(self):
        self.adb_running = False
        process = self.adb_process
        self.adb_process = None

        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=1)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass

        if hasattr(self, "adb_start_btn"):
            self.adb_start_btn.config(state=tk.NORMAL)
            self.adb_stop_btn.config(state=tk.DISABLED)

        if self.source_lines:
            self.status_var.set("ADB stopped")

    def on_close(self):
        self.stop_adb()
        self.destroy()


def main():
    install_global_exception_hooks()
    LOGGER.info(
        "Application starting | Python=%s | platform=%s | crash_log=%s",
        sys.version.replace("\n", " "),
        sys.platform,
        CRASH_LOG_PATH,
    )
    try:
        app = AndroidLogFilterApp()
        app.protocol("WM_DELETE_WINDOW", app.on_close)
        app.mainloop()
    except BaseException:
        LOGGER.critical("Fatal application error", exc_info=True)
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Android Log Filter crashed",
                f"Crash details were saved to:\n{CRASH_LOG_PATH}",
                parent=root,
            )
            root.destroy()
        except Exception:
            pass
        raise
    finally:
        LOGGER.info("Application stopped")


if __name__ == "__main__":
    main()
