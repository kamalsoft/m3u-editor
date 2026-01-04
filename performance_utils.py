import logging
import time
import urllib.request
import urllib.error
import re
from typing import List, Dict, Optional, Any, Callable
from PyQt6.QtCore import QObject, QRunnable, pyqtSignal, QThreadPool, QTimer

# -----------------------------------------------------------------------------
# Throttled Logo Loader
# -----------------------------------------------------------------------------

class LogoSignals(QObject):
    result = pyqtSignal(str, bytes) # url, data
    error = pyqtSignal(str, str)    # url, error_msg

class LogoWorker(QRunnable):
    def __init__(self, url: str, signals: LogoSignals):
        super().__init__()
        self.url = url
        self.signals = signals
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        if self._is_cancelled:
            return
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            req = urllib.request.Request(self.url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = response.read()
                if not self._is_cancelled:
                    self.signals.result.emit(self.url, data)
        except urllib.error.HTTPError as e:
            if not self._is_cancelled:
                self.signals.error.emit(self.url, f"HTTP {e.code}")
        except Exception as e:
            if not self._is_cancelled:
                self.signals.error.emit(self.url, str(e))

class ThrottledLogoLoader(QObject):
    """Manages logo downloads with rate limiting and prioritization."""
    def __init__(self, thread_pool: QThreadPool, max_concurrent: int = 2, delay_ms: int = 500):
        super().__init__()
        self.thread_pool = thread_pool
        self.max_concurrent = max_concurrent
        self.delay_ms = delay_ms
        self.queue: List[str] = []
        self.active_workers: Dict[str, LogoWorker] = {}
        self.signals = LogoSignals()
        
        # Single connections for cleanup
        self.signals.result.connect(self._cleanup_worker)
        self.signals.error.connect(self._cleanup_worker)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self._process_queue)
        self.timer.start(delay_ms)

    def _cleanup_worker(self, url: str, *args):
        if url in self.active_workers:
            del self.active_workers[url]

    def request_logo(self, url: str):
        if url in self.active_workers or url in self.queue:
            return
        self.queue.append(url)

    def _process_queue(self):
        if not self.queue or len(self.active_workers) >= self.max_concurrent:
            return

        url = self.queue.pop(0)
        worker = LogoWorker(url, self.signals)
        self.active_workers[url] = worker
        self.thread_pool.start(worker)

    def cancel_all(self):
        for worker in self.active_workers.values():
            worker.cancel()
        self.active_workers.clear()
        self.queue.clear()

# -----------------------------------------------------------------------------
# Efficient Undo Stack
# -----------------------------------------------------------------------------

class EfficientUndoStack:
    """Saves memory by storing diffs or limited states instead of full deepcopies."""
    def __init__(self, max_depth: int = 50):
        self.max_depth = max_depth
        self.undo_stack: List[Any] = []
        self.redo_stack: List[Any] = []

    def push(self, state: Any):
        # In a real implementation, we might store a diff here.
        # For now, we'll just store the state but ensure we don't exceed max_depth.
        if len(self.undo_stack) >= self.max_depth:
            self.undo_stack.pop(0)
        self.undo_stack.append(state)
        self.redo_stack.clear()

    def undo(self, current_state: Any) -> Optional[Any]:
        if not self.undo_stack:
            return None
        self.redo_stack.append(current_state)
        return self.undo_stack.pop()

    def redo(self, current_state: Any) -> Optional[Any]:
        if not self.redo_stack:
            return None
        self.undo_stack.append(current_state)
        return self.redo_stack.pop()

    def clear(self):
        self.undo_stack.clear()
        self.redo_stack.clear()

# -----------------------------------------------------------------------------
# Fast M3U Parser
# -----------------------------------------------------------------------------

class FastM3UParser:
    """A faster, more robust M3U parser."""
    
    @staticmethod
    def parse_lines(lines: List[str]) -> List[Dict[str, str]]:
        entries = []
        current_entry = {}
        
        for line in lines:
            line = line.strip()
            if not line: continue
            if line.startswith("#EXTM3U"): continue
            
            if line.startswith("#EXTINF:"):
                # Fast attribute extraction without heavy regex
                current_entry = {"raw_extinf": line}
                
                # Split by comma for name
                parts = line.split(",", 1)
                if len(parts) > 1:
                    current_entry["name"] = parts[1].strip()
                
                # Extract attributes from the first part
                attr_part = parts[0]
                # Extract duration
                dur_match = re.search(r'#EXTINF:([-0-9]+)', attr_part)
                if dur_match:
                    current_entry["duration"] = dur_match.group(1)
                
                # Extract other attributes using a simpler regex or string splitting
                for attr in ["group-title", "tvg-logo", "tvg-id", "tvg-chno"]:
                    match = re.search(f'{attr}="([^"]*)"', attr_part)
                    if match:
                        current_entry[attr.replace("-", "_").replace("group_title", "group")] = match.group(1)
            
            elif line.startswith("#EXTVLCOPT:"):
                if "http-user-agent=" in line.lower():
                    current_entry["user_agent"] = line.split("=", 1)[1].strip()
            
            elif not line.startswith("#"):
                if current_entry:
                    current_entry["url"] = line
                    entries.append(current_entry)
                    current_entry = {}
                else:
                    entries.append({"name": "Unknown", "url": line})
                    
        return entries
