import sys
import os
import csv
import re
import subprocess
import zipfile
import glob
import urllib.request
import urllib.error
import urllib.parse
import copy
import xml.etree.ElementTree as ET
import time
import logging
from dataclasses import dataclass
from typing import List, Optional, Iterable, Dict, Any
from performance_utils import ThrottledLogoLoader, EfficientUndoStack, FastM3UParser

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableView, QPushButton, QLabel, QLineEdit,
    QFileDialog, QMessageBox, QHeaderView, QSplitter, QGroupBox, QFormLayout,
    QInputDialog, QAbstractItemView, QProgressBar, QGraphicsOpacityEffect,
    QMenu, QComboBox, QDialog, QDialogButtonBox, QCheckBox, QTabWidget,
    QListView, QStackedWidget, QSpinBox, QTextEdit, QTableWidget, QTableWidgetItem,
    QSlider, QStyle
)
from PyQt6.QtCore import (Qt, QThread, pyqtSignal, QUrl, QPropertyAnimation, 
                          QEasingCurve, QAbstractAnimation, QSettings, QAbstractTableModel,
                          QSortFilterProxyModel, QThreadPool, QRunnable, QObject, QByteArray, QSize, QTimer,
                          QDateTime)
from PyQt6.QtGui import QColor, QPalette, QAction, QPixmap, QIcon, QImage, QStandardItemModel, QStandardItem
from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput, QVideoSink
from PyQt6.QtMultimediaWidgets import QVideoWidget

# -----------------------------------------------------------------------------
# Logging Setup
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("m3u_editor_debug.log", mode='w'),
        logging.StreamHandler()
    ]
)

def exception_hook(exctype, value, traceback):
    logging.error("Uncaught exception", exc_info=(exctype, value, traceback))
    sys.__excepthook__(exctype, value, traceback)

sys.excepthook = exception_hook

# -----------------------------------------------------------------------------
# Data Model
# -----------------------------------------------------------------------------

@dataclass
class M3UEntry:
    """Represents a single channel/stream in the playlist."""
    name: str
    url: str
    group: str = ""
    logo: str = ""
    tvg_id: str = ""
    tvg_chno: str = ""
    duration: str = "-1"
    user_agent: str = ""
    raw_extinf: str = ""  # Keep original attributes to preserve unedited data

    def to_m3u_string(self) -> str:
        """Reconstructs the #EXTINF line and URL line."""
        # We rebuild the EXTINF line based on current properties
        # Basic format: #EXTINF:-1 group-title="Group" tvg-logo="Logo",Name
        
        attributes = []
        if self.group:
            attributes.append(f'group-title="{self.group}"')
        if self.tvg_id:
            attributes.append(f'tvg-id="{self.tvg_id}"')
        if self.logo:
            attributes.append(f'tvg-logo="{self.logo}"')
        if self.tvg_chno:
            attributes.append(f'tvg-chno="{self.tvg_chno}"')
        
        # You can add more specific tvg- tags here if needed
        attr_str = " ".join(attributes)
        
        # If we have attributes, prepend a space
        if attr_str:
            attr_str = " " + attr_str
            
        lines = [f'#EXTINF:{self.duration}{attr_str},{self.name}']
        if self.user_agent:
            lines.append(f'#EXTVLCOPT:http-user-agent={self.user_agent}')
        lines.append(self.url)
        return "\n".join(lines)

# -----------------------------------------------------------------------------
# Logic / Controller
# -----------------------------------------------------------------------------

class M3UParser:
    """Handles reading and writing M3U files."""
    
    @staticmethod
    def parse_lines(lines: Iterable[str]) -> List[M3UEntry]:
        logging.debug("Starting to parse lines...")
        raw_entries = FastM3UParser.parse_lines(list(lines))
        entries = []
        for e in raw_entries:
            entry = M3UEntry(
                name=e.get("name", "Unknown"),
                url=e.get("url", ""),
                group=e.get("group", ""),
                logo=e.get("logo", e.get("tvg_logo", "")),
                tvg_id=e.get("tvg_id", ""),
                tvg_chno=e.get("tvg_chno", ""),
                duration=e.get("duration", "-1"),
                user_agent=e.get("user_agent", ""),
                raw_extinf=e.get("raw_extinf", "")
            )
            entries.append(entry)
        logging.debug(f"Finished parsing. Found {len(entries)} entries.")
        return entries


    @staticmethod
    def parse_file(filepath: str) -> List[M3UEntry]:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return M3UParser.parse_lines(f)
        except Exception as e:
            print(f"Error parsing file: {e}")
            logging.error(f"Error parsing file: {e}", exc_info=True)
            raise e

    @staticmethod
    def save_file(filepath: str, entries: List[M3UEntry], encoding: str = 'utf-8'):
        try:
            with open(filepath, 'w', encoding=encoding) as f:
                f.write("#EXTM3U\n")
                for entry in entries:
                    f.write(entry.to_m3u_string() + "\n")
        except Exception as e:
            raise e

    @staticmethod
    def extract_header_info(lines: List[str]) -> dict:
        info = {}
        for line in lines:
            if line.startswith("#EXTM3U"):
                match = re.search(r'(?:url-tvg|x-tvg-url)="([^"]*)"', line, re.IGNORECASE)
                if match:
                    info['url-tvg'] = match.group(1)
                break
        return info

class ValidationSignals(QObject):
    """Signals for the ValidationWorker."""
    result = pyqtSignal(int, bool, str)   # row_index, is_valid, message
    finished = pyqtSignal()

class ValidationWorker(QRunnable):
    """Worker runnable to check a single stream URL."""
    def __init__(self, row_index, url, user_agent):
        super().__init__()
        self.row_index = row_index # Source row index
        self.url = url
        self.user_agent = user_agent
        self.signals = ValidationSignals()

    def run(self):
        try:
            is_valid, msg = self.check_url(self.url, self.user_agent)
            self.signals.result.emit(self.row_index, is_valid, msg)
        except Exception as e:
            logging.error(f"ValidationWorker failed for row {self.row_index}: {e}", exc_info=True)
        finally:
            self.signals.finished.emit()

    def check_url(self, url, user_agent=None):
        headers = {
            'User-Agent': user_agent if user_agent else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        try:
            req = urllib.request.Request(url, headers=headers, method='HEAD')
            # 5-second timeout
            with urllib.request.urlopen(req, timeout=5) as response:
                if 200 <= response.status < 400:
                    return True, f"OK ({response.status})"
                return False, f"Status: {response.status}"
        except urllib.error.HTTPError as e:
            if e.code == 405: # Method Not Allowed, try GET
                try:
                    req = urllib.request.Request(url, headers=headers, method='GET')
                    with urllib.request.urlopen(req, timeout=5) as response:
                        if 200 <= response.status < 400:
                            return True, f"OK ({response.status})"
                except:
                    pass
            return False, f"HTTP {e.code}"
        except Exception as e:
            return False, f"Error: {str(e)}"

class LogoSignals(QObject):
    result = pyqtSignal(str, bytes) # url, data

class LogoWorker(QRunnable):
    """Worker to download logos in background."""
    def __init__(self, url):
        super().__init__()
        self.url = url
        self.signals = LogoSignals()

    def run(self):
        try:
            with urllib.request.urlopen(self.url, timeout=5) as response:
                data = response.read()
                self.signals.result.emit(self.url, data)
        except Exception as e:
            logging.debug(f"Logo download failed for {self.url}: {e}")

class LogoScrapeSignals(QObject):
    result = pyqtSignal(int, str) # row_index, logo_url
    finished = pyqtSignal()

class LogoScraperWorker(QRunnable):
    """Worker to scrape logo URLs from Google Images."""
    def __init__(self, row_index, channel_name):
        super().__init__()
        self.row_index = row_index
        self.channel_name = channel_name
        self.signals = LogoScrapeSignals()

    def run(self):
        try:
            url = self.find_logo_url(self.channel_name)
            if url:
                self.signals.result.emit(self.row_index, url)
        except Exception as e:
            logging.error(f"LogoScraperWorker failed for {self.channel_name}: {e}", exc_info=True)
        finally:
            self.signals.finished.emit()

    def find_logo_url(self, name):
        try:
            # Search query for TV logos
            query = urllib.parse.quote(f"{name} tv logo png transparent")
            # Use the basic HTML interface of Google Images
            search_url = f"https://www.google.com/search?q={query}&tbm=isch"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            req = urllib.request.Request(search_url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode('utf-8', errors='ignore')
                # Find the first image source (usually a thumbnail in the result set)
                # This regex looks for src="https://..." inside the HTML
                matches = re.findall(r'src="(https://[^"]+)"', html)
                for m in matches:
                    # Filter for likely image hosting domains or google thumbnails
                    if 'gstatic.com' in m or 'googleusercontent.com' in m:
                        return m
        except Exception:
            pass
        return None

class EPGSignals(QObject):
    finished = pyqtSignal(dict, int) # data_map, count
    error = pyqtSignal(str)

class EPGWorker(QRunnable):
    """Worker to fetch and parse XMLTV data."""
    def __init__(self, url):
        super().__init__()
        self.url = url
        self.signals = EPGSignals()

    def run(self):
        try:
            # Download XML
            with urllib.request.urlopen(self.url, timeout=30) as response:
                xml_data = response.read()
            
            # Parse XML
            root = ET.fromstring(xml_data)
            
            # Map: Display Name -> {id, icon}
            epg_map = {}
            count = 0
            
            for channel in root.findall('channel'):
                chn_id = channel.get('id')
                display_name = channel.find('display-name')
                icon = channel.find('icon')
                
                if display_name is not None and display_name.text:
                    name = display_name.text.strip()
                    icon_src = icon.get('src') if icon is not None else ""
                    epg_map[name] = {'id': chn_id, 'logo': icon_src}
                    count += 1
            
            self.signals.finished.emit(epg_map, count)
            
        except Exception as e:
            self.signals.error.emit(str(e))

class RepairWorker(ValidationWorker):
    """Worker to attempt repairing a broken stream."""
    def run(self):
        try:
            # 1. Try Protocol Swap (http <-> https)
            new_url = None
            if self.url.startswith("http://"):
                new_url = self.url.replace("http://", "https://", 1)
            elif self.url.startswith("https://"):
                new_url = self.url.replace("https://", "http://", 1)
                
            if new_url:
                is_valid, msg = self.check_url(new_url, self.user_agent)
                if is_valid:
                    self.signals.result.emit(self.row_index, True, new_url) # Return new URL as message
                    self.signals.finished.emit()
                    return

            self.signals.result.emit(self.row_index, False, "Repair failed")
        except Exception as e:
            logging.error(f"RepairWorker failed for row {self.row_index}: {e}", exc_info=True)
        finally:
            self.signals.finished.emit()

class ResolutionSignals(QObject):
    result = pyqtSignal(int, str) # row_index, resolution
    finished = pyqtSignal()

class ResolutionWorker(QRunnable):
    """Worker to detect stream resolution using ffprobe."""
    def __init__(self, row_index, url):
        super().__init__()
        self.row_index = row_index
        self.url = url
        self.signals = ResolutionSignals()

    def run(self):
        try:
            res = self.get_resolution(self.url)
            if res:
                self.signals.result.emit(self.row_index, res)
        except Exception as e:
            logging.error(f"ResolutionWorker failed for row {self.row_index}: {e}", exc_info=True)
        finally:
            self.signals.finished.emit()

    def get_resolution(self, url):
        try:
            # Requires ffprobe in PATH
            cmd = [
                "ffprobe", "-v", "error", 
                "-select_streams", "v:0", 
                "-show_entries", "stream=width,height", 
                "-of", "csv=s=x:p=0", 
                url
            ]
            # 8 second timeout to prevent hanging
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            if result.returncode == 0:
                output = result.stdout.strip()
                if output and 'x' in output:
                    try:
                        w, h = map(int, output.split('x'))
                        if h >= 2160: return "4K"
                        if h >= 1080: return "1080p"
                        if h >= 720: return "720p"
                        return f"{h}p"
                    except ValueError:
                        return output
        except Exception:
            pass
        return None

class LatencySignals(QObject):
    result = pyqtSignal(int, float, str) # row_index, latency_ms, error
    finished = pyqtSignal()

class LatencyWorker(QRunnable):
    """Worker to measure TTFB latency."""
    def __init__(self, row_index, url):
        super().__init__()
        self.row_index = row_index
        self.url = url
        self.signals = LatencySignals()

    def run(self):
        try:
            start_time = time.time()
            req = urllib.request.Request(self.url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                response.read(1)
            end_time = time.time()
            latency = (end_time - start_time) * 1000
            self.signals.result.emit(self.row_index, latency, "")
        except Exception as e:
            self.signals.result.emit(self.row_index, -1.0, str(e))
        finally:
            self.signals.finished.emit()

class PlaylistModel(QAbstractTableModel):
    """Model to handle playlist data efficiently."""
    request_logo = pyqtSignal(str)

    def __init__(self, entries=None, parent=None):
        super().__init__(parent)
        self.entries = entries or []
        self.headers = ["Group", "Name", "URL"]
        self.validation_data = {}  # id(entry) -> (color, msg, is_valid)
        self.highlight_data = {}   # id(entry) -> color
        self.logo_cache = {}       # url -> QPixmap
        self.pending_logos = set() # urls currently fetching
        self.logo_loader = None # Will be set by window
        self.logo_map = {} # url -> list of row indices

    def rowCount(self, parent=None):
        return len(self.entries)

    def columnCount(self, parent=None):
        return 3

    def rebuild_logo_map(self):
        self.logo_map = {}
        for row, entry in enumerate(self.entries):
            if entry.logo:
                if entry.logo not in self.logo_map:
                    self.logo_map[entry.logo] = []
                self.logo_map[entry.logo].append(row)

    def data(self, index, role):
        if not index.isValid():
            return None
        
        row = index.row()
        if row >= len(self.entries):
            return None
        
        entry = self.entries[row]
        
        if role == Qt.ItemDataRole.DisplayRole:
            if index.column() == 0: return entry.group
            if index.column() == 1: return entry.name
            if index.column() == 2: return entry.url
            
        elif role == Qt.ItemDataRole.UserRole:
            return entry
            
        elif role == Qt.ItemDataRole.UserRole + 1:
            return self.validation_data.get(id(entry), (None, None, None))[2]
            
        elif role == Qt.ItemDataRole.BackgroundRole:
            if id(entry) in self.validation_data:
                return self.validation_data[id(entry)][0]
            return self.highlight_data.get(id(entry))
            
        elif role == Qt.ItemDataRole.ToolTipRole:
            return self.validation_data.get(id(entry), (None, None, None))[1]
            
        elif role == Qt.ItemDataRole.DecorationRole:
            # Show logo in Name column (1) or all columns if needed
            if index.column() == 1 and entry.logo:
                if entry.logo in self.logo_cache:
                    return self.logo_cache[entry.logo]
                elif entry.logo not in self.pending_logos:
                    self.pending_logos.add(entry.logo)
                    if self.logo_loader:
                        self.logo_loader.request_logo(entry.logo)
            return None
            
        return None

    def headerData(self, section, orientation, role):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return None

    def move_rows(self, rows, target_row):
        if not rows: return
        self.beginResetModel()
        items = [self.entries[r] for r in sorted(rows)]
        # Remove in reverse to keep indices valid
        for r in sorted(rows, reverse=True):
            del self.entries[r]
            if r < target_row:
                target_row -= 1
        # Insert at new position
        for item in reversed(items):
            self.entries.insert(target_row, item)
        self.endResetModel()

class PlaylistProxyModel(QSortFilterProxyModel):
    """Proxy model for filtering and sorting."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.filter_text = ""
        self.filter_group = "All Groups"
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def filterAcceptsRow(self, source_row, source_parent):
        model = self.sourceModel()
        if source_row >= len(model.entries):
            return False
            
        entry = model.entries[source_row]
        
        name_match = self.filter_text.lower() in entry.name.lower()
        group_match = (self.filter_group == "All Groups" or entry.group == self.filter_group)
        
        return name_match and group_match

class PlaylistTable(QTableView):
    """Custom TableWidget to handle Drag and Drop reordering."""
    orderChanged = pyqtSignal()
    aboutToChangeOrder = pyqtSignal()

    def dropEvent(self, event):
        if event.source() == self:
            self.aboutToChangeOrder.emit()
            
            # Disable drag-drop if sorted (indices would be messy)
            if self.model().sortColumn() != -1:
                return

            # Handle internal move
            selected_rows = [idx.row() for idx in self.selectionModel().selectedRows()]
            if not selected_rows:
                return

            # Map proxy indices to source indices if necessary
            model = self.model()
            source_model = model
            if isinstance(model, QSortFilterProxyModel):
                source_model = model.sourceModel()
                # If we are not sorted, proxy rows map 1:1 usually, but let's be safe
                # Actually, if not sorted and not filtered, it's 1:1. 
                # If filtered, drag and drop is ambiguous.
                # For safety, we only allow drag/drop if not filtered/sorted.
                if model.filter_text or model.filter_group != "All Groups":
                    return 

            pos = event.position().toPoint()
            index = self.indexAt(pos)
            target_row = index.row() if index.isValid() else model.rowCount()
            
            source_model.move_rows(selected_rows, target_row)
            self.orderChanged.emit()
            event.accept()
        else:
            super().dropEvent(event)

class SettingsDialog(QDialog):
    def __init__(self, parent=None, current_path=""):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.resize(400, 100)
        self.vlc_path = current_path
        
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        self.path_edit = QLineEdit(self.vlc_path)
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(self.browse_path)
        
        row_layout = QHBoxLayout()
        row_layout.addWidget(self.path_edit)
        row_layout.addWidget(btn_browse)
        
        form.addRow("VLC Path:", row_layout)
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def browse_path(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select VLC Executable")
        if path:
            self.path_edit.setText(path)
            
    def get_path(self):
        return self.path_edit.text()

class SaveOptionsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Save Options")
        layout = QVBoxLayout(self)
        
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(["utf-8", "utf-8-sig", "latin-1", "cp1252"])
        
        layout.addWidget(QLabel("Select Encoding:"))
        layout.addWidget(self.encoding_combo)
        
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)
        
    def get_encoding(self):
        return self.encoding_combo.currentText()

class FindReplaceDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Find and Replace")
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        self.find_input = QLineEdit()
        self.replace_input = QLineEdit()
        self.field_combo = QComboBox()
        self.field_combo.addItems(["Name", "URL", "Group"])
        self.case_check = QCheckBox("Case Sensitive")
        
        form.addRow("Find:", self.find_input)
        form.addRow("Replace:", self.replace_input)
        form.addRow("In Field:", self.field_combo)
        form.addRow("", self.case_check)
        
        layout.addLayout(form)
        
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)
        
    def get_data(self):
        return (self.find_input.text(), self.replace_input.text(), 
                self.field_combo.currentText(), self.case_check.isChecked())

class ChannelNumberingDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Channel Numbering Wizard")
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        self.start_num = QSpinBox()
        self.start_num.setRange(1, 999999)
        self.start_num.setValue(1)
        
        self.sort_group = QCheckBox("Sort by Group first")
        self.reset_group = QCheckBox("Reset numbering for each group")
        
        self.target_combo = QComboBox()
        self.target_combo.addItems(["tvg-chno attribute", "Name Prefix (e.g. '1. Name')"])
        
        form.addRow("Start Number:", self.start_num)
        form.addRow("", self.sort_group)
        form.addRow("", self.reset_group)
        form.addRow("Apply to:", self.target_combo)
        
        layout.addLayout(form)
        
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)
        
    def get_settings(self):
        return (self.start_num.value(), self.sort_group.isChecked(), 
                self.reset_group.isChecked(), self.target_combo.currentIndex())

class StoryboardWidget(QWidget):
    """Widget to generate and display a storyboard of frames from a stream."""
    def __init__(self, url="", parent=None):
        super().__init__(parent)
        self.url = url
        self.frames_captured = 0
        self.max_frames = 5
        
        layout = QVBoxLayout(self)
        
        self.status_lbl = QLabel("Ready to generate storyboard.")
        self.status_lbl.setStyleSheet("color: #89b4fa; font-weight: bold;")
        layout.addWidget(self.status_lbl)
        
        self.list_widget = QListView()
        self.list_widget.setViewMode(QListView.ViewMode.IconMode)
        self.list_widget.setResizeMode(QListView.ResizeMode.Adjust)
        self.list_widget.setUniformItemSizes(False)
        self.list_widget.setIconSize(QSize(160, 90))
        self.list_widget.setSpacing(10)
        self.list_widget.setStyleSheet("""
            QListView {
                background-color: #1e1e2e;
                border: 1px solid #313244;
                border-radius: 8px;
            }
            QListView::item {
                color: #cdd6f4;
            }
        """)
        
        self.model = QStandardItemModel()
        self.list_widget.setModel(self.model)
        layout.addWidget(self.list_widget)
        
        self.btn_generate = QPushButton("Generate Storyboard")
        self.btn_generate.clicked.connect(self.start_generation)
        layout.addWidget(self.btn_generate)
        
        # Player setup
        self.player = QMediaPlayer()
        self.audio = QAudioOutput()
        self.audio.setVolume(0) # Mute for storyboard
        self.player.setAudioOutput(self.audio)
        
        self.video_sink = QVideoSink()
        self.player.setVideoSink(self.video_sink)
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.capture_frame)

    def start_generation(self):
        self.model.clear()
        self.frames_captured = 0
        self.btn_generate.setEnabled(False)
        self.status_lbl.setText("Initializing stream...")
        self.player.setSource(QUrl(self.url))
        self.player.play()
        self.timer.start(2000)

    def capture_frame(self):
        frame = self.video_sink.videoFrame()
        if frame.isValid():
            image = frame.toImage()
            pixmap = QPixmap.fromImage(image)
            
            item = QStandardItem()
            item.setIcon(QIcon(pixmap))
            item.setText(f"Frame {self.frames_captured + 1}")
            self.model.appendRow(item)
            
            self.frames_captured += 1
            self.status_lbl.setText(f"Captured {self.frames_captured}/{self.max_frames} frames")
            
            if self.frames_captured >= self.max_frames:
                self.stop_generation()
        else:
            self.status_lbl.setText("Waiting for video frame...")

    def stop_generation(self):
        self.timer.stop()
        self.player.stop()
        self.btn_generate.setEnabled(True)
        self.status_lbl.setText("Storyboard generation complete.")

    def cleanup(self):
        self.timer.stop()
        self.player.stop()
            
    def closeEvent(self, event):
        self.player.stop()
        super().closeEvent(event)

class StreamPreviewDialog(QDialog):
    """Enhanced dialog for live stream preview and storyboard generation."""
    def __init__(self, entry, parent=None):
        super().__init__(parent)
        self.entry = entry
        self.setWindowTitle(f"Preview: {entry.name}")
        self.resize(900, 600)
        
        layout = QVBoxLayout(self)
        
        # Tab Widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # --- Live Preview Tab ---
        self.live_tab = QWidget()
        live_layout = QVBoxLayout(self.live_tab)
        
        # Video Widget
        self.video_widget = QVideoWidget()
        self.video_widget.setMinimumSize(640, 360)
        self.video_widget.setStyleSheet("background-color: black; border-radius: 8px;")
        live_layout.addWidget(self.video_widget)
        
        # Playback Controls
        controls_layout = QHBoxLayout()
        
        self.btn_play_pause = QPushButton()
        self.btn_play_pause.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPause))
        self.btn_play_pause.clicked.connect(self.toggle_playback)
        controls_layout.addWidget(self.btn_play_pause)
        
        self.btn_stop = QPushButton()
        self.btn_stop.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop))
        self.btn_stop.clicked.connect(self.stop_playback)
        controls_layout.addWidget(self.btn_stop)
        
        controls_layout.addStretch()
        
        # Volume Control
        self.btn_mute = QPushButton()
        self.btn_mute.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaVolume))
        self.btn_mute.clicked.connect(self.toggle_mute)
        controls_layout.addWidget(self.btn_mute)
        
        self.volume_slider = QSlider(Qt.Orientation.Horizontal)
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(70)
        self.volume_slider.setFixedWidth(100)
        self.volume_slider.valueChanged.connect(self.set_volume)
        controls_layout.addWidget(self.volume_slider)
        
        # Fullscreen Button
        self.btn_fullscreen = QPushButton()
        self.btn_fullscreen.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_TitleBarMaxButton))
        self.btn_fullscreen.clicked.connect(self.toggle_fullscreen)
        controls_layout.addWidget(self.btn_fullscreen)
        
        live_layout.addLayout(controls_layout)
        
        # Stream Info
        info_group = QGroupBox("Stream Information")
        info_layout = QFormLayout(info_group)
        info_layout.addRow("Name:", QLabel(entry.name))
        info_layout.addRow("Group:", QLabel(entry.group))
        url_lbl = QLabel(entry.url)
        url_lbl.setWordWrap(True)
        info_layout.addRow("URL:", url_lbl)
        live_layout.addWidget(info_group)
        
        self.tabs.addTab(self.live_tab, "Live Preview")
        
        # --- Storyboard Tab ---
        self.storyboard_widget = StoryboardWidget(entry.url)
        self.tabs.addTab(self.storyboard_widget, "Storyboard")
        
        # Media Player Setup
        self.player = QMediaPlayer()
        self.audio_output = QAudioOutput()
        self.player.setAudioOutput(self.audio_output)
        self.player.setVideoOutput(self.video_widget)
        self.audio_output.setVolume(0.7)
        
        self.player.errorOccurred.connect(self.handle_error)
        
        # Start Playback
        self.player.setSource(QUrl(entry.url))
        self.player.play()

    def toggle_playback(self):
        if self.player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self.player.pause()
            self.btn_play_pause.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        else:
            self.player.play()
            self.btn_play_pause.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPause))

    def stop_playback(self):
        self.player.stop()
        self.btn_play_pause.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))

    def set_volume(self, value):
        self.audio_output.setVolume(value / 100.0)
        if value == 0:
            self.btn_mute.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaVolumeMuted))
        else:
            self.btn_mute.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaVolume))

    def toggle_mute(self):
        is_muted = self.audio_output.isMuted()
        self.audio_output.setMuted(not is_muted)
        if not is_muted:
            self.btn_mute.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaVolumeMuted))
        else:
            self.btn_mute.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaVolume))

    def toggle_fullscreen(self):
        if self.video_widget.isFullScreen():
            self.video_widget.showNormal()
        else:
            self.video_widget.showFullScreen()

    def handle_error(self, error, error_str):
        QMessageBox.critical(self, "Playback Error", f"Could not play stream:\n{error_str}")

    def closeEvent(self, event):
        self.player.stop()
        self.storyboard_widget.cleanup()
        super().closeEvent(event)

class StatisticsDialog(QDialog):
    def __init__(self, parent=None, entries=None, validation_data=None):
        super().__init__(parent)
        self.setWindowTitle("Channel Statistics")
        self.resize(600, 500)
        self.entries = entries or []
        self.validation_data = validation_data or {}
        
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        self.create_group_tab()
        self.create_resolution_tab()
        self.create_health_tab()
        
        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def create_table(self, data, headers):
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        
        # Sort data by count desc
        sorted_data = sorted(data.items(), key=lambda x: x[1], reverse=True)
        total = sum(data.values()) if data else 1
        
        table.setRowCount(len(sorted_data))
        for row, (key, count) in enumerate(sorted_data):
            table.setItem(row, 0, QTableWidgetItem(str(key) if key else "Uncategorized"))
            table.setItem(row, 1, QTableWidgetItem(str(count)))
            
            # Percentage Bar
            percent = (count / total) * 100
            progress = QProgressBar()
            progress.setRange(0, 100)
            progress.setValue(int(percent))
            progress.setFormat(f"{percent:.1f}%")
            progress.setStyleSheet("QProgressBar { text-align: center; }")
            table.setCellWidget(row, 2, progress)
            
        return table

    def create_group_tab(self):
        counts = {}
        for entry in self.entries:
            g = entry.group
            counts[g] = counts.get(g, 0) + 1
        
        tab = self.create_table(counts, ["Group", "Count", "Distribution"])
        self.tabs.addTab(tab, "Groups")

    def create_resolution_tab(self):
        counts = {}
        pattern = re.compile(r'\[(\d+p|4K)\]')
        
        for entry in self.entries:
            match = pattern.search(entry.name)
            res = match.group(1) if match else "Unknown"
            counts[res] = counts.get(res, 0) + 1
            
        tab = self.create_table(counts, ["Resolution", "Count", "Distribution"])
        self.tabs.addTab(tab, "Resolution")

    def create_health_tab(self):
        counts = {"Valid": 0, "Invalid": 0, "Untested": 0}
        
        for entry in self.entries:
            # validation_data: id(entry) -> (color, msg, is_valid)
            val_info = self.validation_data.get(id(entry))
            if val_info:
                is_valid = val_info[2]
                if is_valid is True:
                    counts["Valid"] += 1
                elif is_valid is False:
                    counts["Invalid"] += 1
                else:
                    counts["Untested"] += 1
            else:
                counts["Untested"] += 1
                
        tab = self.create_table(counts, ["Status", "Count", "Distribution"])
        self.tabs.addTab(tab, "Health")

# -----------------------------------------------------------------------------
# GUI Implementation
# -----------------------------------------------------------------------------

DARK_STYLESHEET = """
/* Main Window & General */
QMainWindow, QWidget { background-color: #1e1e2e; color: #cdd6f4; font-family: 'Segoe UI', sans-serif; font-size: 10pt; }

/* Buttons */
QPushButton {
    background-color: #313244;
    border: 2px solid #45475a;
    border-radius: 8px;
    padding: 8px 16px;
    font-weight: 600;
}
QPushButton:hover { background-color: #45475a; border-color: #89b4fa; color: #89b4fa; }
QPushButton:pressed { background-color: #585b70; }
QPushButton:disabled { background-color: #1e1e2e; border-color: #313244; color: #6c7086; }

/* Inputs */
QLineEdit {
    background-color: #181825;
    border: 2px solid #313244;
    border-radius: 6px;
    padding: 6px;
    color: #cdd6f4;
}
QLineEdit:focus { border-color: #89b4fa; }

/* Table */
QTableView {
    background-color: #181825;
    alternate-background-color: #1e1e2e;
    border: 1px solid #313244;
    gridline-color: #313244;
    selection-background-color: #313244;
    selection-color: #89b4fa;
}
QHeaderView::section {
    background-color: #1e1e2e;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #89b4fa;
    font-weight: bold;
}

/* Group Box */
QGroupBox {
    border: 2px solid #313244;
    border-radius: 8px;
    margin-top: 1.5em;
    font-weight: bold;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; color: #89b4fa; }

/* Splitter */
QSplitter::handle { background-color: #313244; }

/* Scrollbar */
QScrollBar:vertical { border: none; background: #181825; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #45475a; min-height: 20px; border-radius: 5px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
"""

class M3UEditorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        logging.info("Initializing M3UEditorWindow application...")
        self.setWindowTitle("Open Source M3U Editor")
        self.resize(1000, 700)
        
        self.entries: List[M3UEntry] = []
        self.current_file_path: Optional[str] = None
        self.current_url: Optional[str] = None
        self.thread_pool = QThreadPool()
        # Limit concurrent threads to prevent resource exhaustion/crashes
        self.thread_pool.setMaxThreadCount(5)
        self.validation_pending_count = 0
        self.scrape_pending_count = 0
        self.undo_stack = EfficientUndoStack(max_depth=50)
        self.editing_started = False
        self.is_dark_mode = True # Default to dark mode for "fancy" look
        self.settings = QSettings("OpenSource", "M3UEditor")
        self.recent_files = self.settings.value("recent_files", [], type=list)
        self.epg_url = ""
        
        # Media Player Setup
        self.player = QMediaPlayer()
        self.audio_output = QAudioOutput()
        self.player.setAudioOutput(self.audio_output)
        
        # Apply initial theme
        self.toggle_theme(initial=True)
        
        # Performance Utils
        self.logo_loader = ThrottledLogoLoader(self.thread_pool)
        self.logo_loader.signals.result.connect(self.on_logo_loaded)
        
        self.init_ui()
        self.model.logo_loader = self.logo_loader

    def init_ui(self):
        # Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # --- Menu Bar ---
        self.create_menus()

        # --- Toolbar ---
        toolbar = QHBoxLayout()
        
        # Primary Actions
        btn_add = QPushButton("Add")
        btn_add.setToolTip("Add New Stream")
        btn_add.clicked.connect(self.add_entry)
        
        btn_delete = QPushButton("Delete")
        btn_delete.setToolTip("Delete Selected Streams")
        btn_delete.clicked.connect(self.delete_entry)
        
        self.btn_validate = QPushButton("Check Health")
        self.btn_validate.setToolTip("Validate Stream URLs")
        self.btn_validate.clicked.connect(self.validate_streams)
        
        self.btn_stop = QPushButton("Stop Tasks")
        self.btn_stop.setToolTip("Stop all background processes")
        self.btn_stop.clicked.connect(self.stop_background_tasks)
        self.btn_stop.setEnabled(False)
        
        self.btn_reload = QPushButton("Reload")
        self.btn_reload.setToolTip("Reload current file from disk")
        self.btn_reload.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        self.btn_reload.clicked.connect(self.reload_file)
        
        # Search & Filter
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search channels...")
        self.search_bar.setFixedWidth(200)
        self.search_bar.textChanged.connect(self.filter_table)
        
        self.group_combo = QComboBox()
        self.group_combo.setFixedWidth(150)
        self.group_combo.addItem("All Groups")
        self.group_combo.currentTextChanged.connect(self.filter_table)
        
        toolbar.addWidget(btn_add)
        toolbar.addWidget(btn_delete)
        toolbar.addWidget(self.btn_validate)
        toolbar.addWidget(self.btn_stop)
        toolbar.addWidget(self.btn_reload)
        toolbar.addStretch()
        toolbar.addWidget(QLabel("Filter:"))
        toolbar.addWidget(self.group_combo)
        toolbar.addWidget(self.search_bar)
        
        main_layout.addLayout(toolbar)

        # --- Splitter for Table and Editor ---
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # 1. Left Side: Stacked Widget (Table + Grid)
        self.view_stack = QStackedWidget()
        
        # View 1: Table
        self.table = PlaylistTable()
        self.model = PlaylistModel(self.entries)
        self.model.request_logo.connect(self.fetch_logo) # Connect logo fetcher
        
        self.proxy_model = PlaylistProxyModel()
        self.proxy_model.setSourceModel(self.model)
        self.table.setModel(self.proxy_model)
        
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setDragEnabled(True)
        self.table.setAcceptDrops(True)
        self.table.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.table.setSortingEnabled(True)
        self.table.selectionModel().selectionChanged.connect(self.on_selection_changed)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        # self.table.orderChanged.connect(self.sync_entries_from_table) # No longer needed, model is source of truth
        self.table.aboutToChangeOrder.connect(self.save_undo_state)
        
        self.view_stack.addWidget(self.table)
        
        # View 2: Grid (List View in Icon Mode)
        self.grid_view = QListView()
        self.grid_view.setViewMode(QListView.ViewMode.IconMode)
        self.grid_view.setModel(self.proxy_model)
        self.grid_view.setModelColumn(1) # Use Name column for display/icons
        self.grid_view.setResizeMode(QListView.ResizeMode.Adjust)
        self.grid_view.setUniformItemSizes(True)
        self.grid_view.setGridSize(QSize(120, 100))
        self.grid_view.setSelectionModel(self.table.selectionModel()) # Sync selection
        self.grid_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.grid_view.customContextMenuRequested.connect(self.show_context_menu)
        
        self.view_stack.addWidget(self.grid_view)
        
        splitter.addWidget(self.view_stack)
        
        # 2. Right Side: Editor & Controls
        self.tabs = QTabWidget()
        
        # -- Tab 1: Edit --
        edit_tab = QWidget()
        edit_layout = QVBoxLayout(edit_tab)
        
        form_layout = QFormLayout()
        self.input_name = QLineEdit()
        self.input_name.textChanged.connect(self.update_current_entry_data)
        
        self.input_group = QLineEdit()
        self.input_group.textChanged.connect(self.update_current_entry_data)
        
        self.input_tvg_id = QLineEdit()
        self.input_tvg_id.textChanged.connect(self.update_current_entry_data)
        
        self.input_chno = QLineEdit()
        self.input_chno.textChanged.connect(self.update_current_entry_data)
        
        self.input_logo = QLineEdit()
        self.input_logo.textChanged.connect(self.update_current_entry_data)
        
        self.input_url = QLineEdit()
        self.input_url.textChanged.connect(self.update_current_entry_data)
        
        self.input_user_agent = QLineEdit()
        self.input_user_agent.textChanged.connect(self.update_current_entry_data)
        
        form_layout.addRow("Name:", self.input_name)
        form_layout.addRow("Group:", self.input_group)
        form_layout.addRow("EPG ID:", self.input_tvg_id)
        form_layout.addRow("Channel #:", self.input_chno)
        form_layout.addRow("Logo URL:", self.input_logo)
        form_layout.addRow("Stream URL:", self.input_url)
        form_layout.addRow("User Agent:", self.input_user_agent)
        
        edit_layout.addLayout(form_layout)
        edit_layout.addStretch()
        
        # -- Tab 2: Preview --
        preview_tab = QWidget()
        preview_layout = QVBoxLayout(preview_tab)

        self.video_widget = QVideoWidget()
        self.video_widget.setMinimumHeight(250)
        self.player.setVideoOutput(self.video_widget)
        
        btn_preview_layout = QHBoxLayout()
        btn_play = QPushButton("Play")
        btn_play.clicked.connect(self.play_stream)
        btn_stop = QPushButton("Stop")
        btn_stop.clicked.connect(self.stop_stream)
        
        btn_preview_layout.addWidget(btn_play)
        btn_preview_layout.addWidget(btn_stop)
        
        preview_layout.addWidget(self.video_widget)
        preview_layout.addLayout(btn_preview_layout)
        preview_layout.addStretch()
        
        # -- Tab 3: Actions --
        actions_tab = QWidget()
        actions_layout = QVBoxLayout(actions_tab)
        
        btn_up = QPushButton("Move Up")
        btn_up.clicked.connect(self.move_up)
        
        btn_down = QPushButton("Move Down")
        btn_down.clicked.connect(self.move_down)
        
        btn_bulk_group = QPushButton("Batch Edit Group")
        btn_bulk_group.clicked.connect(self.bulk_edit_group)
        
        btn_bulk_ua = QPushButton("Batch Edit User-Agent")
        btn_bulk_ua.clicked.connect(self.batch_edit_user_agent)
        
        actions_layout.addWidget(btn_up)
        actions_layout.addWidget(btn_down)
        actions_layout.addWidget(btn_bulk_group)
        actions_layout.addWidget(btn_bulk_ua)
        actions_layout.addStretch()
        
        # -- Tab 4: History --
        history_tab = QWidget()
        history_layout = QVBoxLayout(history_tab)
        self.history_log = QTextEdit()
        self.history_log.setReadOnly(True)
        history_layout.addWidget(self.history_log)
        
        self.tabs.addTab(edit_tab, "Edit")
        self.tabs.addTab(preview_tab, "Preview")
        self.tabs.addTab(actions_tab, "Actions")
        self.tabs.addTab(history_tab, "History")
        
        splitter.addWidget(self.tabs)
        
        # Set initial sizes for splitter (70% table, 30% editor)
        splitter.setSizes([700, 300])
        
        main_layout.addWidget(splitter)
        
        # Status Bar
        self.status_label = QLabel("Ready")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedWidth(200)
        self.statusBar().addPermanentWidget(self.progress_bar)
        self.statusBar().addWidget(self.status_label)

    def create_menus(self):
        menubar = self.menuBar()
        
        # File Menu
        file_menu = menubar.addMenu("File")
        
        load_action = QAction("Load M3U File", self)
        load_action.triggered.connect(self.load_m3u)
        file_menu.addAction(load_action)
        
        load_url_action = QAction("Load from URL", self)
        load_url_action.triggered.connect(self.load_m3u_from_url)
        file_menu.addAction(load_url_action)
        
        merge_action = QAction("Merge Playlist...", self)
        merge_action.triggered.connect(self.merge_m3u)
        file_menu.addAction(merge_action)
        
        save_action = QAction("Save M3U", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_m3u)
        file_menu.addAction(save_action)
        
        save_enc_action = QAction("Save with Encoding...", self)
        save_enc_action.triggered.connect(self.save_m3u_encoded)
        file_menu.addAction(save_enc_action)
        
        restore_action = QAction("Restore Backup...", self)
        restore_action.triggered.connect(self.restore_backup)
        file_menu.addAction(restore_action)
        
        # Recent Files Submenu
        self.recent_menu = file_menu.addMenu("Open Recent")
        self.update_recent_menu()
        
        file_menu.addSeparator()
        
        export_action = QAction("Export to CSV", self)
        export_action.triggered.connect(self.export_csv)
        file_menu.addAction(export_action)
        
        # Edit Menu
        edit_menu = menubar.addMenu("Edit")
        
        undo_action = QAction("Undo", self)
        undo_action.setShortcut("Ctrl+Z")
        undo_action.triggered.connect(self.undo)
        edit_menu.addAction(undo_action)
        
        redo_action = QAction("Redo", self)
        redo_action.setShortcut("Ctrl+Y")
        redo_action.triggered.connect(self.redo)
        edit_menu.addAction(redo_action)
        
        edit_menu.addSeparator()
        
        find_action = QAction("Find and Replace...", self)
        find_action.setShortcut("Ctrl+F")
        find_action.triggered.connect(self.find_replace)
        edit_menu.addAction(find_action)
        
        # Tools Menu
        tools_menu = menubar.addMenu("Tools")
        
        dup_action = QAction("Find Duplicates", self)
        dup_action.triggered.connect(self.find_duplicates)
        tools_menu.addAction(dup_action)
        
        invalid_action = QAction("Remove Invalid Streams", self)
        invalid_action.triggered.connect(self.remove_invalid_streams)
        tools_menu.addAction(invalid_action)
        
        chno_action = QAction("Channel Numbering Wizard...", self)
        chno_action.triggered.connect(self.open_channel_numbering)
        tools_menu.addAction(chno_action)
        
        repair_action = QAction("Auto-Repair Broken Streams", self)
        repair_action.triggered.connect(self.auto_repair_streams)
        tools_menu.addAction(repair_action)
        
        res_action = QAction("Check Resolutions", self)
        res_action.triggered.connect(self.check_resolutions)
        tools_menu.addAction(res_action)
        
        latency_action = QAction("Check Stream Latency", self)
        latency_action.triggered.connect(self.check_latency)
        tools_menu.addAction(latency_action)
        
        stats_action = QAction("Channel Statistics...", self)
        stats_action.triggered.connect(self.open_statistics)
        tools_menu.addAction(stats_action)
        
        epg_action = QAction("Update EPG Data...", self)
        epg_action.triggered.connect(self.update_epg_data)
        tools_menu.addAction(epg_action)
        
        smart_group_action = QAction("Smart Grouping...", self)
        smart_group_action.triggered.connect(self.smart_group_channels)
        tools_menu.addAction(smart_group_action)
        
        flag_action = QAction("Add Country Flags...", self)
        flag_action.triggered.connect(self.add_country_flags)
        tools_menu.addAction(flag_action)
        
        scrape_action = QAction("Scrape Missing Logos...", self)
        scrape_action.triggered.connect(self.scrape_logos)
        tools_menu.addAction(scrape_action)
        
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.open_settings)
        tools_menu.addAction(settings_action)
        
        # View Menu
        view_menu = menubar.addMenu("View")
        theme_action = QAction("Toggle Dark Mode", self)
        theme_action.triggered.connect(lambda: self.toggle_theme(initial=False))
        view_menu.addAction(theme_action)
        
        view_mode_action = QAction("Toggle Grid/List View", self)
        view_mode_action.setShortcut("Ctrl+G")
        view_mode_action.triggered.connect(self.toggle_view_mode)
        view_menu.addAction(view_mode_action)

    # -------------------------------------------------------------------------
    # Actions
    # -------------------------------------------------------------------------

    def log_action(self, message):
        """Logs an action to the history tab."""
        timestamp = QDateTime.currentDateTime().toString("HH:mm:ss")
        logging.info(f"Action: {message}")
        self.history_log.append(f"[{timestamp}] {message}")

    def stop_background_tasks(self):
        """Stops all pending background tasks."""
        self.thread_pool.clear()
        self.validation_pending_count = 0
        self.scrape_pending_count = 0
        
        # Reset UI state
        self.progress_bar.setVisible(False)
        self.status_label.setText("Background tasks stopped.")
        self.btn_validate.setEnabled(True)
        self.btn_stop.setEnabled(False)
        
        self.log_action("Stopped all background tasks")

    def create_backup(self, reason="auto"):
        """Creates a zip backup of the current playlist."""
        if not self.entries: return
        
        backup_dir = os.path.join(os.getcwd(), "backups")
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = QDateTime.currentDateTime().toString("yyyyMMdd_HHmmss")
        filename = f"backup_{timestamp}_{reason}.zip"
        filepath = os.path.join(backup_dir, filename)
        
        try:
            with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zf:
                content = "#EXTM3U\n" + "\n".join(e.to_m3u_string() for e in self.entries)
                zf.writestr("playlist.m3u", content)
            self.log_action(f"Backup created: {filename}")
        except Exception as e:
            self.log_action(f"Backup failed: {str(e)}")

    def restore_backup(self):
        backup_dir = os.path.join(os.getcwd(), "backups")
        if not os.path.exists(backup_dir):
            QMessageBox.information(self, "Restore", "No backups found.")
            return
            
        files = sorted(glob.glob(os.path.join(backup_dir, "*.zip")), reverse=True)
        if not files:
            QMessageBox.information(self, "Restore", "No backups found.")
            return
            
        filenames = [os.path.basename(f) for f in files]
        item, ok = QInputDialog.getItem(self, "Restore Backup", "Select backup to restore:", filenames, 0, False)
        
        if ok and item:
            filepath = os.path.join(backup_dir, item)
            try:
                with zipfile.ZipFile(filepath, 'r') as zf:
                    with zf.open("playlist.m3u") as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        lines = content.splitlines()
                        
                self.save_undo_state()
                self.entries = M3UParser.parse_lines(lines)
                self.model.entries = self.entries
                self.refresh_table()
                self.update_group_combo()
                self.log_action(f"Restored backup: {item}")
                QMessageBox.information(self, "Success", "Backup restored successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not restore backup: {str(e)}")

    def save_undo_state(self):
        """Saves the current state of entries to the undo stack."""
        self.undo_stack.push(self.entries)

    def undo(self):
        prev_state = self.undo_stack.undo(self.entries)
        if prev_state is not None:
            self.entries = prev_state
            self.model.entries = self.entries
            self.refresh_table(clear_cache=False)
            self.update_group_combo()
            self.log_action("Undo performed")
        else:
            self.status_label.setText("Nothing to undo.")

    def redo(self):
        next_state = self.undo_stack.redo(self.entries)
        if next_state is not None:
            self.entries = next_state
            self.model.entries = self.entries
            self.refresh_table(clear_cache=False)
            self.update_group_combo()
            self.log_action("Redo performed")
        else:
            self.status_label.setText("Nothing to redo.")

    def load_m3u(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open M3U File", "", "M3U Files (*.m3u *.m3u8);;All Files (*)")
        if file_name:
            logging.info(f"Attempting to load M3U file: {file_name}")
            try:
                self.undo_stack.clear()
                self.entries = M3UParser.parse_file(file_name)
                
                # Try to extract EPG URL from header
                with open(file_name, 'r', encoding='utf-8', errors='ignore') as f:
                    self.epg_url = M3UParser.extract_header_info(f.readlines()[:5]).get('url-tvg', "")
                    head = []
                    for _ in range(5):
                        try: head.append(next(f))
                        except StopIteration: break
                    self.epg_url = M3UParser.extract_header_info(head).get('url-tvg', "")
                
                self.model.entries = self.entries # Update model reference
                self.current_file_path = file_name
                self.current_url = None
                self.setWindowTitle(f"Open Source M3U Editor - {os.path.basename(file_name)}")
                self.add_recent_file(file_name)
                self.refresh_table()
                self.update_group_combo()
                self.status_label.setText(f"Loaded {len(self.entries)} channels from {file_name}")
                self.log_action(f"Loaded file: {os.path.basename(file_name)}")
            except Exception as e:
                logging.error(f"Failed to load M3U file: {e}", exc_info=True)
                QMessageBox.critical(self, "Error", f"Could not load file: {str(e)}")

    def add_recent_file(self, path):
        if path in self.recent_files:
            self.recent_files.remove(path)
        self.recent_files.insert(0, path)
        self.recent_files = self.recent_files[:10] # Keep last 10
        self.settings.setValue("recent_files", self.recent_files)
        self.update_recent_menu()

    def update_recent_menu(self):
        self.recent_menu.clear()
        for path in self.recent_files:
            action = QAction(os.path.basename(path), self)
            action.setToolTip(path)
            action.triggered.connect(lambda checked, p=path: self.load_recent_file(p))
            self.recent_menu.addAction(action)
            
    def load_recent_file(self, path):
        if not os.path.exists(path):
            QMessageBox.warning(self, "Error", "File not found.")
            return
        logging.info(f"Loading recent file: {path}")
        try:
            self.undo_stack.clear()
            self.entries = M3UParser.parse_file(path)
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                self.epg_url = M3UParser.extract_header_info(f.readlines()[:5]).get('url-tvg', "")
                head = []
                for _ in range(5):
                    try: head.append(next(f))
                    except StopIteration: break
                self.epg_url = M3UParser.extract_header_info(head).get('url-tvg', "")

            self.model.entries = self.entries
            self.current_file_path = path
            self.current_url = None
            self.setWindowTitle(f"Open Source M3U Editor - {os.path.basename(path)}")
            self.add_recent_file(path)
            self.refresh_table()
            self.update_group_combo()
            self.log_action(f"Loaded recent file: {os.path.basename(path)}")
        except Exception as e:
            logging.error(f"Failed to load recent file: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Could not load file: {str(e)}")

    def reload_file(self):
        """Reloads the currently open file or URL."""
        if self.current_file_path:
            logging.info(f"Reloading file: {self.current_file_path}")
            self.load_recent_file(self.current_file_path)
            self.status_label.setText(f"Reloaded: {os.path.basename(self.current_file_path)}")
        elif self.current_url:
            logging.info(f"Reloading URL: {self.current_url}")
            self.load_m3u_from_url(self.current_url)
            self.status_label.setText("Reloaded from URL")
        else:
            QMessageBox.information(self, "Reload", "No source is currently open to reload.")

    def load_m3u_from_url(self, url=None):
        if not url:
            url, ok = QInputDialog.getText(self, "Load M3U from URL", "Enter Playlist URL:")
            if not ok or not url:
                return
                
        logging.info(f"Loading M3U from URL: {url}")
        try:
            with urllib.request.urlopen(url) as response:
                content = response.read().decode('utf-8', errors='ignore')
                lines = content.splitlines()
            
            self.undo_stack.clear()
            self.entries = M3UParser.parse_lines(lines)
            self.epg_url = M3UParser.extract_header_info(lines[:5]).get('url-tvg', "")
            self.model.entries = self.entries
            self.current_file_path = None # No local file path
            self.current_url = url
            self.setWindowTitle(f"Open Source M3U Editor - URL Stream")
            self.refresh_table()
            self.update_group_combo()
            self.status_label.setText(f"Loaded {len(self.entries)} channels from URL")
            self.log_action("Loaded playlist from URL")
        except Exception as e:
            logging.error(f"Failed to load URL: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Could not load URL: {str(e)}")

    def merge_m3u(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Merge M3U File", "", "M3U Files (*.m3u *.m3u8);;All Files (*)")
        if file_name:
            try:
                self.create_backup("before_merge")
                new_entries = M3UParser.parse_file(file_name)
                if not new_entries:
                    return
                self.save_undo_state()
                self.entries.extend(new_entries)
                self.refresh_table()
                self.update_group_combo()
                self.status_label.setText(f"Merged {len(new_entries)} channels from {os.path.basename(file_name)}")
                QMessageBox.information(self, "Success", f"Merged {len(new_entries)} channels.")
                self.log_action(f"Merged {len(new_entries)} channels from {os.path.basename(file_name)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not merge file: {str(e)}")

    def save_m3u(self):
        if not self.entries:
            QMessageBox.warning(self, "Warning", "No entries to save.")
            return

        file_name, _ = QFileDialog.getSaveFileName(self, "Save M3U File", self.current_file_path or "playlist.m3u", "M3U Files (*.m3u *.m3u8)")
        if file_name:
            try:
                self.create_backup("before_save")
                M3UParser.save_file(file_name, self.entries)
                self.current_file_path = file_name
                self.setWindowTitle(f"Open Source M3U Editor - {os.path.basename(file_name)}")
                self.status_label.setText(f"Saved to {file_name}")
                QMessageBox.information(self, "Success", "File saved successfully!")
                self.log_action(f"Saved file: {os.path.basename(file_name)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not save file: {str(e)}")

    def save_m3u_encoded(self):
        if not self.entries:
            QMessageBox.warning(self, "Warning", "No entries to save.")
            return

        file_name, _ = QFileDialog.getSaveFileName(self, "Save M3U File", self.current_file_path or "playlist.m3u8", "M3U8 Files (*.m3u8);;M3U Files (*.m3u)")
        if file_name:
            dlg = SaveOptionsDialog(self)
            if dlg.exec():
                encoding = dlg.get_encoding()
                try:
                    self.create_backup("before_save_enc")
                    M3UParser.save_file(file_name, self.entries, encoding)
                    self.current_file_path = file_name
                    self.setWindowTitle(f"Open Source M3U Editor - {os.path.basename(file_name)}")
                    self.status_label.setText(f"Saved to {file_name} ({encoding})")
                    QMessageBox.information(self, "Success", f"File saved successfully with {encoding} encoding!")
                    self.log_action(f"Saved file with encoding {encoding}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Could not save file: {str(e)}")

    def export_csv(self):
        if not self.entries:
            QMessageBox.warning(self, "Warning", "No entries to export.")
            return

        file_name, _ = QFileDialog.getSaveFileName(self, "Export CSV", "playlist.csv", "CSV Files (*.csv)")
        if file_name:
            try:
                with open(file_name, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Group", "Name", "URL", "Logo", "Duration", "User-Agent"])
                    for entry in self.entries:
                        writer.writerow([entry.group, entry.name, entry.url, entry.logo, entry.duration, entry.user_agent])
                self.status_label.setText(f"Exported to {file_name}")
                QMessageBox.information(self, "Success", "Export successful!")
                self.log_action(f"Exported CSV: {os.path.basename(file_name)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not export: {str(e)}")

    def refresh_table(self, clear_cache=True):
        """Reloads the table widget from the self.entries list."""
        logging.debug("Refreshing table view...")
        self.model.beginResetModel()
        self.model.validation_data.clear()
        self.model.highlight_data.clear()
        if clear_cache:
            self.model.logo_cache.clear()
        self.model.rebuild_logo_map()
        self.model.endResetModel()
        logging.debug("Table refresh complete.")
        # self.animate_table_refresh() # Animation can be glitchy with proxy resets

    def get_selected_rows(self):
        """Helper to get selected rows, handling both Table and Grid views."""
        selection_model = self.table.selectionModel()
        rows = selection_model.selectedRows()
        if rows:
            return rows
        # Fallback for Grid View (IconMode) where selectedRows() returns empty
        indexes = selection_model.selectedIndexes()
        if indexes:
            # Filter for unique rows
            seen_rows = set()
            unique_rows = []
            for idx in indexes:
                if idx.row() not in seen_rows:
                    seen_rows.add(idx.row())
                    unique_rows.append(idx)
            return unique_rows
        return []

    def on_selection_changed(self):
        """Populates the editor panel when a row is selected."""
        selected_rows = self.get_selected_rows()
        if selected_rows:
            # Map proxy index to source index
            proxy_index = selected_rows[0]
            source_index = self.proxy_model.mapToSource(proxy_index)
            row = source_index.row()
            
            # Retrieve entry from the item data to support sorting
            entry = self.entries[row]
            self.editing_started = False
            
            # Block signals to prevent 'textChanged' from triggering updates while we populate
            self.input_name.blockSignals(True)
            self.input_group.blockSignals(True)
            self.input_logo.blockSignals(True)
            self.input_tvg_id.blockSignals(True)
            self.input_chno.blockSignals(True)
            self.input_url.blockSignals(True)
            self.input_user_agent.blockSignals(True)
            
            self.input_name.setText(entry.name)
            self.input_group.setText(entry.group)
            self.input_logo.setText(entry.logo)
            self.input_url.setText(entry.url)
            self.input_tvg_id.setText(entry.tvg_id)
            self.input_chno.setText(entry.tvg_chno)
            self.input_user_agent.setText(entry.user_agent)
            
            self.input_name.blockSignals(False)
            self.input_group.blockSignals(False)
            self.input_logo.blockSignals(False)
            self.input_url.blockSignals(False)
            self.input_user_agent.blockSignals(False)
            self.input_tvg_id.blockSignals(False)
            self.input_chno.blockSignals(False)
        else:
            self.clear_editor()

    def clear_editor(self):
        self.input_name.blockSignals(True)
        self.input_group.blockSignals(True)
        self.input_tvg_id.blockSignals(True)
        self.input_chno.blockSignals(True)
        self.input_logo.blockSignals(True)
        self.input_url.blockSignals(True)
        self.input_user_agent.blockSignals(True)

        self.input_name.clear()
        self.input_group.clear()
        self.input_tvg_id.clear()
        self.input_chno.clear()
        self.input_logo.clear()
        self.input_url.clear()
        self.input_user_agent.clear()
        
        self.input_name.blockSignals(False)
        self.input_group.blockSignals(False)
        self.input_tvg_id.blockSignals(False)
        self.input_chno.blockSignals(False)
        self.input_logo.blockSignals(False)
        self.input_url.blockSignals(False)
        self.input_user_agent.blockSignals(False)

    def update_current_entry_data(self):
        """Updates the data model when the user types in the editor fields."""
        selected_rows = self.get_selected_rows()
        if not selected_rows:
            return
            
        proxy_index = selected_rows[0]
        source_index = self.proxy_model.mapToSource(proxy_index)
        row = source_index.row()
        entry = self.entries[row]
        
        if not self.editing_started:
            self.save_undo_state()
            self.editing_started = True
        
        old_logo = entry.logo
        entry.name = self.input_name.text()
        entry.group = self.input_group.text()
        entry.tvg_id = self.input_tvg_id.text()
        entry.tvg_chno = self.input_chno.text()
        entry.logo = self.input_logo.text()
        entry.url = self.input_url.text()
        entry.user_agent = self.input_user_agent.text()
        
        if entry.logo != old_logo:
            self.model.rebuild_logo_map()
            
        # Update table display immediately (optional, but looks nice)
        self.model.dataChanged.emit(self.model.index(row, 0), self.model.index(row, 2))

    def add_entry(self):
        self.save_undo_state()
        new_entry = M3UEntry(name="New Channel", url="http://", group="Uncategorized")
        self.entries.append(new_entry)
        self.refresh_table()
        # Select the new item
        self.model.layoutChanged.emit()
        self.log_action("Added new entry")
        # Find the new item in the proxy model to select it
        source_index = self.model.index(len(self.entries) - 1, 0)
        proxy_index = self.proxy_model.mapFromSource(source_index)
        if proxy_index.isValid():
            self.table.selectRow(proxy_index.row())

    def delete_entry(self):
        selected_rows = self.get_selected_rows()
        if not selected_rows:
            return
            
        count = len(selected_rows)
        confirm = QMessageBox.question(self, "Confirm Delete", f"Are you sure you want to delete {count} channel(s)?", 
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if confirm == QMessageBox.StandardButton.Yes:
            self.create_backup("before_delete")
            self.save_undo_state()
            # Remove rows in reverse order to maintain correct indices during deletion
            self.model.beginResetModel()
            # Convert all proxy indices to source indices
            source_indices = [self.proxy_model.mapToSource(idx) for idx in selected_rows]
            
            for index in sorted(source_indices, key=lambda x: x.row(), reverse=True):
                del self.entries[index.row()]
            self.model.rebuild_logo_map()
            self.model.endResetModel()
            self.clear_editor()
            self.log_action(f"Deleted {count} entries")

    def move_up(self):
        self.save_undo_state()
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        # Map to source
        proxy_index = selected_rows[0]
        source_index = self.proxy_model.mapToSource(proxy_index)
        row = source_index.row()
        
        if row > 0:
            # Swap in list
            self.entries[row], self.entries[row-1] = self.entries[row-1], self.entries[row]
            # Refresh and keep selection
            self.model.layoutChanged.emit()
            # Re-select based on new source position
            new_source_index = self.model.index(row - 1, 0)
            new_proxy_index = self.proxy_model.mapFromSource(new_source_index)
            if new_proxy_index.isValid():
                self.table.selectRow(new_proxy_index.row())

    def move_down(self):
        self.save_undo_state()
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        proxy_index = selected_rows[0]
        source_index = self.proxy_model.mapToSource(proxy_index)
        row = source_index.row()
        
        if row < len(self.entries) - 1:
            # Swap in list
            self.entries[row], self.entries[row+1] = self.entries[row+1], self.entries[row]
            self.model.layoutChanged.emit()
            new_source_index = self.model.index(row + 1, 0)
            new_proxy_index = self.proxy_model.mapFromSource(new_source_index)
            if new_proxy_index.isValid():
                self.table.selectRow(new_proxy_index.row())

    def update_group_combo(self):
        current = self.group_combo.currentText()
        self.group_combo.blockSignals(True)
        self.group_combo.clear()
        self.group_combo.addItem("All Groups")
        
        groups = sorted(list(set(entry.group for entry in self.entries if entry.group)))
        self.group_combo.addItems(groups)
        
        if current in groups:
            self.group_combo.setCurrentText(current)
        self.group_combo.blockSignals(False)

    def filter_table(self):
        self.proxy_model.filter_text = self.search_bar.text()
        self.proxy_model.filter_group = self.group_combo.currentText()
        self.proxy_model.invalidateFilter()

    def bulk_edit_group(self):
        selected_indices = self.get_selected_rows()
        if not selected_indices:
            QMessageBox.warning(self, "Warning", "No channels selected.")
            return
            
        new_group, ok = QInputDialog.getText(self, "Bulk Edit Group", "Enter new group name:")
        if ok:
            self.create_backup("bulk_group")
            self.save_undo_state()
            
            # Capture source rows before modification
            rows = [self.proxy_model.mapToSource(idx).row() for idx in selected_indices]
            
            for row in rows:
                if 0 <= row < len(self.entries):
                    self.entries[row].group = new_group
            
            self.refresh_table(clear_cache=False)
            self.update_group_combo()
            self.log_action(f"Bulk edited group for {len(rows)} items")

    def batch_edit_user_agent(self):
        selected_indices = self.get_selected_rows()
        if not selected_indices:
            QMessageBox.warning(self, "Warning", "No channels selected.")
            return
            
        new_ua, ok = QInputDialog.getText(self, "Batch Edit User-Agent", "Enter new User-Agent:")
        if ok:
            self.create_backup("batch_ua")
            self.save_undo_state()
            
            # Capture source rows before modification
            rows = [self.proxy_model.mapToSource(idx).row() for idx in selected_indices]
            
            for row in rows:
                if 0 <= row < len(self.entries):
                    self.entries[row].user_agent = new_ua
            
            self.refresh_table(clear_cache=False)
            self.log_action(f"Batch edited User-Agent for {len(rows)} items")

    def find_replace(self):
        dlg = FindReplaceDialog(self)
        if dlg.exec():
            find_text, replace_text, field, case_sens = dlg.get_data()
            if not find_text:
                return
                
            self.create_backup("find_replace")
            self.save_undo_state()
            count = 0
            for entry in self.entries:
                val = getattr(entry, field.lower(), "")
                if not case_sens:
                    if find_text.lower() in val.lower():
                        setattr(entry, field.lower(), re.sub(re.escape(find_text), replace_text, val, flags=re.IGNORECASE))
                        count += 1
                elif find_text in val:
                    setattr(entry, field.lower(), val.replace(find_text, replace_text))
                    count += 1
            
            self.refresh_table()
            QMessageBox.information(self, "Result", f"Replaced {count} occurrences.")
            self.log_action(f"Find & Replace: {count} occurrences of '{find_text}'")

    def open_channel_numbering(self):
        dlg = ChannelNumberingDialog(self)
        if dlg.exec():
            start, sort_by_group, reset_per_group, target_mode = dlg.get_settings()
            self.create_backup("numbering")
            self.save_undo_state()
            
            # If sorting is requested
            if sort_by_group:
                self.entries.sort(key=lambda x: (x.group, x.name))
            
            current_num = start
            last_group = None
            
            for entry in self.entries:
                if reset_per_group and entry.group != last_group:
                    current_num = start
                    last_group = entry.group
                
                if target_mode == 0: # tvg-chno
                    entry.tvg_chno = str(current_num)
                else: # Name Prefix
                    # Remove existing prefix if it looks like "123. "
                    entry.name = re.sub(r'^\d+\.\s*', '', entry.name)
                    entry.name = f"{current_num}. {entry.name}"
                
                current_num += 1
            
            self.refresh_table()
            QMessageBox.information(self, "Success", "Channel numbering applied.")
            self.log_action("Applied channel numbering")

    def sync_entries_from_table(self):
        """No longer needed with QAbstractTableModel as self.entries is the source of truth."""
        pass

    def validate_streams(self):
        # If already validating, maybe stop? 
        # QThreadPool doesn't support easy "stop all", so we just let them finish 
        # or we could implement a flag in workers. For now, we just start new ones.
        # To keep it simple, we won't implement a hard stop button for the pool.

        # Determine rows to validate
        selected_rows = self.table.selectionModel().selectedRows()
        rows_to_check = []
        
        if selected_rows:
            for index in selected_rows:
                source_index = self.proxy_model.mapToSource(index)
                row = source_index.row()
                entry = self.entries[row]
                rows_to_check.append((row, entry.url, entry.user_agent))
        else:
            # Check ALL rows (source), not just visible ones, or visible ones?
            # "Check All" usually implies all.
            # If filter is active, maybe just visible? Let's do visible rows to respect filter.
            for row in range(self.proxy_model.rowCount()):
                proxy_index = self.proxy_model.index(row, 0)
                source_index = self.proxy_model.mapToSource(proxy_index)
                entry = self.entries[source_index.row()]
                rows_to_check.append((source_index.row(), entry.url, entry.user_agent))

        if not rows_to_check:
            return

        logging.info(f"Starting validation for {len(rows_to_check)} streams.")
        self.btn_validate.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(rows_to_check))
        self.status_label.setText(f"Validating {len(rows_to_check)} streams...")
        
        self.validation_pending_count = len(rows_to_check)

        for row, url, ua in rows_to_check:
            worker = ValidationWorker(row, url, ua)
            worker.signals.result.connect(self.on_validation_result)
            worker.signals.finished.connect(self.on_validation_finished_one)
            self.thread_pool.start(worker)

    def on_validation_finished_one(self):
        self.validation_pending_count -= 1
        val = self.progress_bar.maximum() - self.validation_pending_count
        self.progress_bar.setValue(val)
        
        if self.validation_pending_count == 0:
            self.btn_stop.setEnabled(False)
        
        if self.validation_pending_count <= 0:
            self.on_validation_complete()

    def on_validation_result(self, row_index, is_valid, message):
        if self.is_dark_mode:
            color = QColor("#1b5e20") if is_valid else QColor("#b71c1c") # Darker Green/Red
        else:
            color = QColor("#c8e6c9") if is_valid else QColor("#ffcdd2") # Light Green/Red
            
        if row_index < len(self.entries):
            entry = self.entries[row_index]
            self.model.validation_data[id(entry)] = (color, message, is_valid)
            self.model.dataChanged.emit(self.model.index(row_index, 0), self.model.index(row_index, 2))

    def on_validation_complete(self):
        self.btn_validate.setText("Check Stream Health")
        self.btn_validate.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Validation complete.")
        logging.info("Validation complete.")
        self.log_action("Stream validation completed")

    def check_resolutions(self):
        selected_rows = self.table.selectionModel().selectedRows()
        rows_to_check = []
        
        if selected_rows:
            for index in selected_rows:
                source_index = self.proxy_model.mapToSource(index)
                row = source_index.row()
                entry = self.entries[row]
                rows_to_check.append((row, entry.url))
        else:
            # Check visible rows
            for row in range(self.proxy_model.rowCount()):
                proxy_index = self.proxy_model.index(row, 0)
                source_index = self.proxy_model.mapToSource(proxy_index)
                entry = self.entries[source_index.row()]
                rows_to_check.append((source_index.row(), entry.url))
                
        if not rows_to_check: return
        self.btn_stop.setEnabled(True)
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_label.setText(f"Checking resolution for {len(rows_to_check)} streams...")
        
        for row, url in rows_to_check:
            worker = ResolutionWorker(row, url)
            worker.signals.result.connect(self.on_resolution_found)
            self.thread_pool.start(worker)
            
    def on_resolution_found(self, row, res_str):
        entry = self.entries[row]
        if res_str and res_str not in entry.name:
            entry.name = f"{entry.name} [{res_str}]"
            self.model.dataChanged.emit(self.model.index(row, 1), self.model.index(row, 1))

    def check_latency(self):
        selected_rows = self.table.selectionModel().selectedRows()
        rows_to_check = []
        
        if selected_rows:
            for index in selected_rows:
                source_index = self.proxy_model.mapToSource(index)
                row = source_index.row()
                entry = self.entries[row]
                rows_to_check.append((row, entry.url))
        else:
            # Check visible rows
            for row in range(self.proxy_model.rowCount()):
                proxy_index = self.proxy_model.index(row, 0)
                source_index = self.proxy_model.mapToSource(proxy_index)
                entry = self.entries[source_index.row()]
                rows_to_check.append((source_index.row(), entry.url))
                
        if not rows_to_check: return
        self.btn_stop.setEnabled(True)
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_label.setText(f"Checking latency for {len(rows_to_check)} streams...")
        
        for row, url in rows_to_check:
            worker = LatencyWorker(row, url)
            worker.signals.result.connect(self.on_latency_result)
            self.thread_pool.start(worker)

    def on_latency_result(self, row, latency, error):
        if row < len(self.entries) and latency >= 0:
            entry = self.entries[row]
            entry.name = re.sub(r'\s*\[\d+ms\]', '', entry.name)
            entry.name = f"{entry.name} [{int(latency)}ms]"
            self.model.dataChanged.emit(self.model.index(row, 1), self.model.index(row, 1))

    def auto_repair_streams(self):
        # Find invalid streams first
        broken_rows = []
        for row, entry in enumerate(self.entries):
            # Check validation data
            is_valid = self.model.validation_data.get(id(entry), (None, None, None))[2]
            if is_valid is False:
                broken_rows.append(row)
        
        if not broken_rows:
            QMessageBox.information(self, "Info", "No known broken streams. Run 'Check Health' first.")
            return

        self.create_backup("auto_repair")
        self.save_undo_state()
        self.btn_stop.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(broken_rows))
        self.status_label.setText(f"Attempting repair on {len(broken_rows)} streams...")
        
        self.validation_pending_count = len(broken_rows)
        self.repaired_count = 0

        for row in broken_rows:
            entry = self.entries[row]
            worker = RepairWorker(row, entry.url, entry.user_agent)
            worker.signals.result.connect(self.on_repair_result)
            worker.signals.finished.connect(self.on_validation_finished_one) # Reuse progress logic
            self.thread_pool.start(worker)
        logging.info(f"Started auto-repair on {len(broken_rows)} streams")
        self.log_action(f"Started auto-repair on {len(broken_rows)} streams")

    def on_repair_result(self, row_index, success, result_data):
        if success:
            # result_data is the new URL
            entry = self.entries[row_index]
            entry.url = result_data
            self.repaired_count += 1
            # Update model
            self.model.validation_data[id(entry)] = (QColor("#c8e6c9"), "Repaired", True)
            self.model.dataChanged.emit(self.model.index(row_index, 0), self.model.index(row_index, 2))

    def update_epg_data(self):
        url, ok = QInputDialog.getText(self, "Update EPG", "Enter XMLTV URL:", text=self.epg_url)
        if not ok or not url:
            return
            
        self.epg_url = url # Remember it
        self.status_label.setText("Downloading and parsing EPG...")
        self.btn_stop.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0) # Indeterminate
        
        worker = EPGWorker(url)
        worker.signals.finished.connect(self.on_epg_loaded)
        worker.signals.error.connect(lambda err: QMessageBox.critical(self, "Error", f"EPG Error: {err}"))
        self.thread_pool.start(worker)

    def on_epg_loaded(self, epg_map, count):
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"EPG Parsed: {count} channels found.")
        self.btn_stop.setEnabled(False)
        
        if not epg_map:
            return
            
        self.save_undo_state()
        matched = 0
        
        # Match entries
        for entry in self.entries:
            # Simple matching by name (case-insensitive)
            # Could be improved with fuzzy matching
            name_key = entry.name.strip()
            
            # Try exact match first, then case insensitive
            data = epg_map.get(name_key)
            if not data:
                # Try finding case-insensitive match in keys
                # This is slow for large lists, but acceptable for typical playlist sizes
                for k, v in epg_map.items():
                    if k.lower() == name_key.lower():
                        data = v
                        break
            
            if data:
                if not entry.tvg_id:
                    entry.tvg_id = data['id']
                    matched += 1
                if not entry.logo and data['logo']:
                    entry.logo = data['logo']
        
        self.refresh_table()
        QMessageBox.information(self, "Success", f"Updated {matched} channels with EPG data.")
        self.log_action(f"Updated EPG data for {matched} channels")
        
    def smart_group_channels(self):
        categories = {
            "Sports": ["sport", "espn", "nba", "nfl", "soccer", "football", "tennis", "golf", "f1", "racing", "beinsports"],
            "News": ["news", "cnn", "bbc", "msnbc", "fox", "al jazeera", "weather", "info"],
            "Movies": ["movie", "film", "cinema", "hbo", "starz", "showtime", "drama", "action", "comedy", "thriller"],
            "Kids": ["cartoon", "disney", "nick", "animation", "anime", "kids", "baby", "jr"],
            "Music": ["music", "mtv", "vh1", "radio", "hits", "pop", "rock", "dance"],
            "Documentary": ["docu", "history", "discovery", "nat geo", "planet", "wild", "science"]
        }
        
        reply = QMessageBox.question(self, "Smart Grouping", 
                                     "This will categorize channels based on their names.\n"
                                     "Existing groups will be overwritten only if a match is found.\n\n"
                                     "Continue?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply != QMessageBox.StandardButton.Yes:
            return
            
        self.create_backup("smart_group")
        self.save_undo_state()
        count = 0
        
        try:
            for entry in self.entries:
                name_lower = entry.name.lower()
                found_group = None
                
                for category, keywords in categories.items():
                    for keyword in keywords:
                        if keyword in name_lower:
                            found_group = category
                            break
                    if found_group:
                        break
                
                if found_group:
                    if entry.group != found_group:
                        entry.group = found_group
                        count += 1
                        
            self.refresh_table()
            self.update_group_combo()
            QMessageBox.information(self, "Success", f"Categorized {count} channels.")
            self.log_action(f"Smart Grouping categorized {count} channels")
        except Exception as e:
            logging.error(f"Smart Grouping failed: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Smart Grouping failed: {str(e)}")

    def add_country_flags(self):
        flags = {
            "US": "🇺🇸", "USA": "🇺🇸", "United States": "🇺🇸", "America": "🇺🇸",
            "UK": "🇬🇧", "Great Britain": "🇬🇧", "United Kingdom": "🇬🇧", "London": "🇬🇧",
            "CA": "🇨🇦", "Canada": "🇨🇦",
            "FR": "🇫🇷", "France": "🇫🇷", "French": "🇫🇷",
            "DE": "🇩🇪", "Germany": "🇩🇪", "German": "🇩🇪",
            "IT": "🇮🇹", "Italy": "🇮🇹", "Italian": "🇮🇹",
            "ES": "🇪🇸", "Spain": "🇪🇸", "Spanish": "🇪🇸",
            "BR": "🇧🇷", "Brazil": "🇧🇷",
            "RU": "🇷🇺", "Russia": "🇷🇺",
            "JP": "🇯🇵", "Japan": "🇯🇵",
            "CN": "🇨🇳", "China": "🇨🇳",
            "IN": "🇮🇳", "India": "🇮🇳",
            "AU": "🇦🇺", "Australia": "🇦🇺",
            "TR": "🇹🇷", "Turkey": "🇹🇷",
            "PL": "🇵🇱", "Poland": "🇵🇱",
            "NL": "🇳🇱", "Netherlands": "🇳🇱",
            "BE": "🇧🇪", "Belgium": "🇧🇪",
            "SE": "🇸🇪", "Sweden": "🇸🇪",
            "CH": "🇨🇭", "Switzerland": "🇨🇭",
            "PT": "🇵🇹", "Portugal": "🇵🇹",
            "GR": "🇬🇷", "Greece": "🇬🇷",
            "AR": "🇦🇷", "Argentina": "🇦🇷",
            "MX": "🇲🇽", "Mexico": "🇲🇽",
            "CO": "🇨🇴", "Colombia": "🇨🇴",
        }
        
        reply = QMessageBox.question(self, "Add Country Flags", 
                                     "This will attempt to detect countries from channel names and add flags to the group title.\n\nContinue?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply != QMessageBox.StandardButton.Yes:
            return
            
        self.create_backup("add_flags")
        self.save_undo_state()
        count = 0
        
        try:
            for entry in self.entries:
                name_upper = entry.name.upper()
                found_flag = None
                
                for key, flag in flags.items():
                    # Regex: Word boundary or start/end of string, case insensitive
                    pattern = r'(?:^|[\s\(\[\-\_])' + re.escape(key) + r'(?:$|[\s\)\]\-\_])'
                    if re.search(pattern, name_upper, re.IGNORECASE):
                        found_flag = flag
                        break
                
                if found_flag:
                    if found_flag not in entry.group:
                        if entry.group:
                            entry.group = f"{found_flag} {entry.group}"
                        else:
                            entry.group = f"{found_flag} Uncategorized"
                        count += 1
                        
            self.refresh_table()
            self.update_group_combo()
            QMessageBox.information(self, "Success", f"Added flags to {count} channels.")
            self.log_action(f"Added country flags to {count} channels")
        except Exception as e:
            logging.error(f"Add Country Flags failed: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Operation failed: {str(e)}")

    def scrape_logos(self):
        selected_rows = self.table.selectionModel().selectedRows()
        rows_to_check = []
        
        if selected_rows:
            for index in selected_rows:
                source_index = self.proxy_model.mapToSource(index)
                row = source_index.row()
                entry = self.entries[row]
                if not entry.logo:
                    rows_to_check.append((row, entry.name))
        else:
            # Check all rows with missing logos
            for row, entry in enumerate(self.entries):
                if not entry.logo:
                    rows_to_check.append((row, entry.name))
        
        if not rows_to_check:
            QMessageBox.information(self, "Info", "No channels found with missing logos (or none selected).")
            return

        reply = QMessageBox.question(self, "Logo Scraper", 
                                     f"Found {len(rows_to_check)} channels without logos.\n"
                                     "Scraping Google Images may trigger rate limits if done too quickly.\n"
                                     "Do you want to proceed?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.create_backup("logo_scrape")
        self.save_undo_state()
        
        self.btn_stop.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(rows_to_check))
        self.status_label.setText(f"Scraping logos for {len(rows_to_check)} channels...")
        
        self.scrape_pending_count = len(rows_to_check)
        
        logging.info(f"Starting logo scrape for {len(rows_to_check)} channels.")
        for row, name in rows_to_check:
            worker = LogoScraperWorker(row, name)
            worker.signals.result.connect(self.on_scrape_result)
            worker.signals.finished.connect(self.on_scrape_finished_one)
            self.thread_pool.start(worker)
            
    def on_scrape_result(self, row, url):
        if row < len(self.entries):
            entry = self.entries[row]
            entry.logo = url
            # Update model
            self.model.dataChanged.emit(self.model.index(row, 0), self.model.index(row, 2))
            
    def on_scrape_finished_one(self):
        self.scrape_pending_count -= 1
        val = self.progress_bar.maximum() - self.scrape_pending_count
        self.progress_bar.setValue(val)
        if self.scrape_pending_count == 0: self.btn_stop.setEnabled(False)
        
        if self.scrape_pending_count <= 0:
            self.progress_bar.setVisible(False)
            self.status_label.setText("Logo scraping complete.")
            self.log_action("Logo scraping completed")
            QMessageBox.information(self, "Success", "Logo scraping complete.")

    def fetch_logo(self, url):
        # logging.debug(f"Fetching logo: {url}") # Can be verbose
        worker = LogoWorker(url)
        worker.signals.result.connect(self.on_logo_loaded)
        self.thread_pool.start(worker)
        
    def on_logo_loaded(self, url, data):
        pixmap = QPixmap()
        if pixmap.loadFromData(data):
            # Scale for grid view
            pixmap = pixmap.scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self.model.logo_cache[url] = pixmap
            self.model.pending_logos.discard(url)
            
            # Use logo_map for targeted updates instead of full layoutChanged
            if url in self.model.logo_map:
                for row in self.model.logo_map[url]:
                    if 0 <= row < len(self.entries):
                        idx = self.model.index(row, 1)
                        self.model.dataChanged.emit(idx, idx, [Qt.ItemDataRole.DecorationRole])

    def find_duplicates(self):
        seen_urls = set()
        duplicate_rows = []
        
        self.model.highlight_data.clear()

        for i, entry in enumerate(self.entries):
            if entry.url in seen_urls:
                duplicate_rows.append(i)
            else:
                seen_urls.add(entry.url)

        if not duplicate_rows:
            QMessageBox.information(self, "Duplicates", "No duplicate URLs found.")
            return

        self.table.clearSelection()
        for row in duplicate_rows:
            # Highlight visually
            entry = self.entries[row]
            self.model.highlight_data[id(entry)] = QColor("#fff9c4")
            # Select the row
            source_index = self.model.index(row, 0)
            proxy_index = self.proxy_model.mapFromSource(source_index)
            if proxy_index.isValid():
                self.table.selectRow(proxy_index.row())

        reply = QMessageBox.question(
            self, 
            "Duplicates Found", 
            f"Found {len(duplicate_rows)} duplicates.\nDo you want to delete them now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.create_backup("dedupe")
            self.delete_entry()
        else:
            self.model.layoutChanged.emit() # Refresh to show highlights

    def play_stream(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if selected_rows:
            proxy_index = selected_rows[0]
            source_index = self.proxy_model.mapToSource(proxy_index)
            entry = self.entries[source_index.row()]
            self.player.setSource(QUrl(entry.url))
            self.player.play()

    def stop_stream(self):
        self.player.stop()

    def remove_invalid_streams(self):
        rows_to_remove = []
        # Iterate over source entries directly
        for row, entry in enumerate(self.entries):
            # Check validation data
            is_valid = self.model.validation_data.get(id(entry), (None, None, None))[2]
            if is_valid is False: # Explicitly False (failed validation)
                rows_to_remove.append(row)
        
        if not rows_to_remove:
            QMessageBox.information(self, "Info", "No invalid streams found (run validation first).")
            return

        confirm = QMessageBox.question(self, "Confirm", f"Remove {len(rows_to_remove)} invalid streams?")
        if confirm == QMessageBox.StandardButton.Yes:
            self.create_backup("remove_invalid")
            self.save_undo_state()
            self.model.beginResetModel()
            # Remove in reverse order to maintain indices
            for row in sorted(rows_to_remove, reverse=True):
                del self.entries[row]
            self.model.endResetModel()
            QMessageBox.information(self, "Success", "Invalid streams removed.")

    def toggle_theme(self, initial=False):
        app = QApplication.instance()
        
        if not initial:
            self.is_dark_mode = not self.is_dark_mode
            
        if self.is_dark_mode:
            app.setStyleSheet(DARK_STYLESHEET)
        else:
            app.setStyleSheet("") # Revert to default Fusion/System style
            app.setStyle("Fusion")

    def toggle_view_mode(self):
        if self.view_stack.currentIndex() == 0:
            self.view_stack.setCurrentIndex(1) # Show Grid
        else:
            self.view_stack.setCurrentIndex(0) # Show Table

    def animate_table_refresh(self):
        """Fade animation for the table."""
        effect = QGraphicsOpacityEffect(self.table)
        self.table.setGraphicsEffect(effect)
        
        self.anim = QPropertyAnimation(effect, b"opacity")
        self.anim.setDuration(500)
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        self.anim.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)

    def add_to_favorites(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        self.save_undo_state()
        for index in selected_rows:
            source_index = self.proxy_model.mapToSource(index)
            row = source_index.row()
            entry = self.entries[row]
            entry.group = "Favorites"
            
        self.refresh_table()
        self.update_group_combo()
        QMessageBox.information(self, "Success", "Added selected channels to Favorites.")
        self.log_action(f"Added {len(selected_rows)} channels to Favorites")

    def show_context_menu(self, position):
        menu = QMenu()
        
        fav_action = QAction("Add to Favorites", self)
        fav_action.triggered.connect(self.add_to_favorites)
        menu.addAction(fav_action)
        
        menu.addSeparator()
        
        play_vlc_action = QAction("Open in VLC", self)
        play_vlc_action.triggered.connect(self.open_in_vlc)
        menu.addAction(play_vlc_action)
        
        preview_action = QAction("Stream Preview (Storyboard)", self)
        preview_action.triggered.connect(self.open_stream_preview)
        menu.addAction(preview_action)
        
        # Handle context menu for both views
        sender = self.sender()
        if isinstance(sender, (QTableView, QListView)):
            menu.exec(sender.viewport().mapToGlobal(position))

    def open_settings(self):
        current_path = self.settings.value("vlc_path", "")
        dlg = SettingsDialog(self, current_path)
        if dlg.exec():
            new_path = dlg.get_path()
            self.settings.setValue("vlc_path", new_path)

    def open_in_vlc(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        proxy_index = selected_rows[0]
        source_index = self.proxy_model.mapToSource(proxy_index)
        entry = self.entries[source_index.row()]
        if not entry:
            return

        # Check settings first
        vlc_cmd = self.settings.value("vlc_path", "")
        
        if not vlc_cmd or not os.path.exists(vlc_cmd):
            vlc_cmd = "vlc"
            if sys.platform == "win32":
                # Check common locations if vlc is not in path
                possible_paths = [
                    os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "VideoLAN", "VLC", "vlc.exe"),
                    os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "VideoLAN", "VLC", "vlc.exe")
                ]
                for p in possible_paths:
                    if os.path.exists(p):
                        vlc_cmd = p
                        break
        
        try:
            if sys.platform == 'darwin':
                 subprocess.Popen(['open', '-a', 'VLC', entry.url])
            else:
                 subprocess.Popen([vlc_cmd, entry.url])
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not start VLC: {e}\nEnsure VLC is installed and in your PATH.")

    def open_stream_preview(self):
        selected_indices = self.get_selected_rows()
        if not selected_indices:
            return
            
        proxy_index = selected_indices[0]
        source_index = self.proxy_model.mapToSource(proxy_index)
        entry = self.entries[source_index.row()]
        
        dlg = StreamPreviewDialog(entry, self)
        dlg.exec()

    def open_statistics(self):
        dlg = StatisticsDialog(self, self.entries, self.model.validation_data)
        dlg.exec()

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Optional: Set a dark theme style for a "tech" look
    app.setStyle("Fusion")
    
    window = M3UEditorWindow()
    window.show()
    
    sys.exit(app.exec())
