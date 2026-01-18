# Technical Specifications & Architecture

This document outlines the technical architecture, class structure, and data flow of the Open Source M3U Editor. It is intended to assist developers and GenAI models in understanding the codebase for future updates.

## 1. Architecture Overview

The application follows a **Model-View-Controller (MVC)** pattern implemented via PyQt6.

*   **Model**: `PlaylistModel` (subclass of `QAbstractTableModel`) holds the list of `M3UEntry` objects. It manages data display, validation status, and logo caching.
*   **View**: 
    *   `PlaylistTable` (`QTableView`) for the detailed list view.
    *   `QListView` for the icon/grid view.
    *   `StreamPreviewDialog` for video playback and details.
*   **Controller**: `M3UEditorWindow` (`QMainWindow`) acts as the main controller, handling user interactions, menu actions, and coordinating background workers.

## 2. Core Components

### 2.1 Data Structures
*   **`M3UEntry` (dataclass)**: Represents a single playlist item.
    *   Attributes: `name`, `url`, `group`, `logo`, `tvg_id`, `tvg_chno`, `duration`, `user_agent`, `favorite`, `health_status`, `raw_extinf`.
    *   Methods: `to_m3u_string()` reconstructs the entry for file saving.

### 2.2 Main Window (`M3UEditorWindow`)
*   **State Management**:
    *   `entries`: List of `M3UEntry`.
    *   `undo_stack`: Instance of `EfficientUndoStack`.
    *   `thread_pool`: `QThreadPool` for handling background tasks.
*   **UI Layout**:
    *   Uses `QSplitter` to divide the main view (Table/Grid) from the Editor/Preview panel.
    *   `QStackedWidget` switches between Table and Grid views.

### 2.3 Performance Utilities (`performance_utils.py`)
*   **`FastM3UParser`**: A regex-light parser optimized for speed. It iterates through lines and splits strings rather than using complex pattern matching for every line.
*   **`ThrottledLogoLoader`**: Manages logo downloads. It uses a queue and a timer to prevent flooding the network or UI thread with image updates.
*   **`EfficientUndoStack`**: Manages history. *Note: Currently stores full state snapshots. Future optimization could implement delta/diff storage.*

## 3. Threading Model

The application relies heavily on `QThreadPool` and `QRunnable` to keep the UI responsive.

### Worker Classes
| Class | Purpose | Signals |
|-------|---------|---------|
| `ValidationWorker` | Performs HTTP HEAD/GET requests to check stream availability. | `result(row, valid, msg)` |
| `LogoWorker` | Downloads image data from a URL. | `result(url, data)` |
| `LogoScraperWorker` | Scrapes Google Images results for a channel name. | `result(row, url)` |
| `EPGWorker` | Fetches and parses XMLTV files (supports .gz, .xz). | `finished(data, count)`, `progress(msg)` |
| `ResolutionWorker` | Uses `subprocess` to call `ffprobe` and detect video resolution. | `result(row, resolution)` |
| `LatencyWorker` | Measures Time-To-First-Byte (TTFB). | `result(row, ms, error)` |
| `SecurityAuditWorker` | Checks SSL, Content-Type, and redirects. | `result(row, dict)` |
| `StalkerWorker` | Authenticates and fetches playlist from Stalker Middleware portals. | `finished(entries)`, `error(msg)` |
| `CastConnectWorker` | Handles connection to Chromecast devices. | `success()`, `error(msg)` |
| `CastDiscoveryWorker` | Scans for Chromecast devices. | `found(cast)`, `finished()` |
| `NetworkScannerWorker` | Scans for UPnP/DLNA devices via SSDP. | `found(name, loc)`, `finished()` |
| `SpeedTestWorker` | Measures download speed. | `progress(int)`, `result(str)`, `error(str)` |
| `FFmpegWorker` | Runs FFmpeg commands for transcoding/recording. | `output(str)`, `finished()`, `error(str)` |
| `DiagnosticsWorker` | Runs ffprobe for stream analysis. | `result(dict)`, `error(str)` |
| `LogoWizardWorker` | Matches logos from a repository. | `found(row, url)`, `finished(count)` |

**Note on Thread Safety**: Workers emit signals to communicate with the main thread. Direct modification of the `entries` list or UI widgets from workers is avoided.

## 4. External Dependencies

### Python Packages
*   `PyQt6`: Core GUI framework.
*   `requests`: (Implicitly replaced by `urllib` in current code to reduce deps, but standard for this type of app).

### System Binaries
*   **VLC**: Required for the "Open in VLC" feature. The app attempts to auto-detect the path or uses the user-configured path in Settings.
*   **FFmpeg (ffprobe)**: Required for the `ResolutionWorker`. Must be in the system PATH.

## 5. Key Features Implementation Details

### 5.1 EPG Integration
*   **Parsing**: Uses `xml.etree.ElementTree`.
*   **Compression**: Detects `.gz` and `.xz` extensions and decompresses in memory before parsing.
*   **Matching**: Currently matches EPG data to Channels via `tvg-id` or exact Name match.

### 5.2 Stream Preview
*   Uses `QMediaPlayer` and `QVideoWidget`.
*   **Storyboard**: Uses `QVideoSink` to capture video frames at intervals and displays them in a `QListView` with `IconMode`.

### 5.3 Smart Grouping
*   Uses a dictionary of Regex patterns (`categories`) to classify channels based on keywords in their names.
*   Supports optional resolution detection and country flag detection during grouping.

### 5.4 Plugin System
*   **`PluginManager`**: Discovers and loads Python scripts from the `plugins/` directory.
*   **Interface**: Plugins must define a `run(window)` function which receives the main window instance.

### 5.5 Task Scheduler
*   **Implementation**: Uses `QTimer` in the main window to check for scheduled tasks (Backup, EPG, Validation) every minute against `QSettings`.

## 6. Known Issues & Future Work

### 6.1 Missing Components
*   **`RepairWorker`**: The method `auto_repair_streams` attempts to instantiate `RepairWorker`, but this class definition is missing from the source code.
    *   *Action Required*: Implement `RepairWorker` to handle logic for finding alternative stream URLs or fixing malformed URLs.

### 6.2 Optimization Opportunities
*   **EPG Matching**: Fuzzy matching (e.g., using Levenshtein distance) could improve EPG mapping for channels with slightly different names.
*   **Undo Stack**: Implement true delta compression for the undo stack to reduce memory usage with very large playlists.

## 7. File Structure

```text
/
├── m3u_editor.py          # Main application entry point and GUI logic
├── performance_utils.py   # Helper classes for threading and parsing
├── readme.md              # User documentation
├── TECHNICAL_SPECS.md     # Technical documentation (this file)
└── backups/               # Auto-generated directory for zip backups
```