# Open Source M3U Editor

A robust, cross-platform GUI application built with Python and PyQt6 for managing, editing, and organizing M3U/M3U8 playlists. Optimized for performance and security.

## Features

### 🚀 Playlist Management
*   **Universal Loading**: Load M3U/M3U8 files, download from URLs, or login via **Xtream Codes API** and **Stalker Portal**.
*   **Merge & Split**: Merge multiple playlists with strategies (Append, Replace, Deduplicate) or split a playlist into separate files by Group.
*   **Export**: Save with custom encoding or export metadata to CSV.
*   **History**: Robust Undo/Redo system and action logging.
*   **Backup & Restore**: Automatic ZIP-based backups before major operations; easy restore wizard.

### 🛠️ Editing & Organization
*   **Bulk Editing**: Batch edit Groups, User-Agents, or specific attributes for selected channels.
*   **User-Agent Manager**: Centralized management of User-Agents; apply to groups, selection, or all channels.
*   **Smart Grouping**: Regex-based auto-categorization (Sports, Movies, News, etc.) with resolution and country detection.
*   **Channel Numbering**: Wizard to renumber channels, sort by group, and apply prefixes.
*   **Find & Replace**: Advanced search with Regular Expression support.
*   **Playlist Diff**: Compare the current playlist with another file to identify added, removed, or modified channels.
*   **Deduplication**:
    *   **Find Duplicates**: Identify and highlight or batch delete duplicate URLs.
    *   **Smart Dedupe**: Intelligent removal keeping the entry with the highest resolution or most metadata.
    *   **Fuzzy Finder**: Detect duplicates based on name similarity (e.g., "BBC One" vs "BBC 1").
*   **Logo Tools**:
    *   **Scraper**: Find missing logos via Google Images.
    *   **Wizard**: Match logos from a repository URL.
    *   **Local Logos**: Browse and assign local image files to channels.
*   **Country Flags**: Auto-detect country from channel names and append flags to group titles.
*   **Language Tools**:
    *   **Quick Translate**: Translate channel names to a target language.
    *   **Language Manager**: Customize regex patterns for language detection.

### 📺 Playback & Preview
*   **Stream Preview**: Live video preview with playback controls, aspect ratio, speed control, and audio/subtitle track selection.
*   **IPTV Player Mode**: Dedicated full-screen interface with channel list, search, and **Picture-in-Picture (PiP)** support.
*   **Storyboard**: Generate frame-by-frame visual storyboards of streams.
*   **Snapshot Gallery**: View, manage, and export captured snapshots.
*   **Casting**:
    *   **Chromecast/DLNA**: Cast streams to devices on your network.
    *   **Cast Manager**: Control volume, seek, stop, and manage a **Cast Queue** for continuous playback.
    *   **Remote Control**: Dockable widget and Status Bar Mini-Player for quick cast control.
    *   **Mobile Casting**: Generate QR codes to play streams on mobile devices via WiFi.
    *   **Sleep Timer**: Automatically stop casting after a set duration.
*   **Network Scanner**: Discover local UPnP/DLNA media devices.

### 🛡️ Diagnostics & Security
*   **Health Check**: Validate streams via asynchronous HTTP HEAD/GET requests.
*   **Live Stream Monitor**: Dashboard to continuously monitor the health of selected streams.
*   **Security Audit**: Scan for SSL validity, suspicious content types, redirects, and reputation.
*   **Stream Diagnostics**: Detailed technical analysis (Codec, Bitrate, Resolution) using `ffprobe`.
*   **Resolution & Latency**: Detect stream resolution (SD, HD, 4K) and measure response time (TTFB).
*   **Auto-Repair**: Attempt to fix broken streams (protocol swaps, redirect following).
*   **Broken Link Reporter**: Generate text reports of invalid streams.

### ⚙️ Advanced Tools
*   **Transcode Wizard**: Convert streams to MP4, MKV, or TS formats using `ffmpeg`.
*   **Scheduled Recording**: Record live streams for a set duration.
*   **Network Speed Test**: Integrated download speed test.
*   **Cloud Sync**: Save and load playlists from local cloud folders (Google Drive, Dropbox, OneDrive).
*   **EPG Integration**: Load XMLTV EPGs (supports .gz/.xz), cache locally, and view program schedules.
*   **Task Scheduler**: Automate backups, EPG updates, and playlist validation.
*   **Plugin System**: Extend functionality with external Python scripts.
*   **Version Control**: Track playlist changes with a local Git repository.

### 🎨 UI & Customization
*   **Theme Editor**: Customize application colors and save themes.
*   **Dark Mode**: Built-in dark theme with platform-specific font rendering.
*   **Quick Access Toolbar**: Pin your favorite actions for easy access.
*   **Global Search**: Filter playlist by Name, Group, URL, or EPG ID.
*   **Language Column**: Display and filter channels by detected language.
*   **Virtual List View**: Efficient handling of large playlists (10k+ channels).
*   **Network Monitor**: Real-time bandwidth usage display in the status bar.

## Demo

*Visual overview of the application features.*

## Prerequisites

*   Python 3.x
*   PyQt6
*   **FFmpeg/ffprobe**: Required for Resolution Checker, Diagnostics, Transcoding, and Recording.
*   **pychromecast**: Required for Casting features.
*   **VLC**: Optional, for external playback.
*   **qrcode**: Required for Mobile Casting (QR Code generation).
*   **deep-translator**: Required for Quick Translate feature.

## Build & Deployment

### Desktop (Windows & macOS)
To create a standalone executable/application for your operating system:

1.  Install the build requirements:
    ```bash
    pip install -r requirements.txt
    ```
2.  Run the build script:
    ```bash
    python build_app.py
    ```
3.  Find your application in the `dist/` folder.

### Android & Google TV
While this application is built with Python and Qt (which supports Android), porting it to a mobile/TV interface requires additional steps:
1.  **Tooling**: Use **BeeWare (Briefcase)** or **PyQt-Deploy**.
2.  **UI Adaptation**: The current interface is optimized for mouse/keyboard. For TV usage, the UI would need to be adapted for D-Pad navigation.
3.  **Build**: Once adapted, you can generate an APK using `briefcase build android`.

## Installation

1.  Clone the repository or download the source code.
2.  Install the required dependencies:

```bash
pip install PyQt6 pychromecast qrcode[pil] deep-translator
```

*Note: Depending on your OS, you might need additional codecs for the video preview to work with all stream types.*

## Usage

### Getting Started
1.  **Launch**: Run the application via the executable or `python m3u_editor.py`.
2.  **First Run**: Follow the wizard to configure your VLC path and default EPG sources.

### Menu & Feature Guide

#### **File Menu**
*   **New**: Create a blank playlist.
*   **Load M3U File**: Open a local `.m3u` or `.m3u8` file.
*   **Load from URL**: Download a playlist directly from a web link.
*   **Load from Xtream Codes**: Login to an IPTV provider using Host, Username, and Password.
*   **Load from Stalker Portal**: Login using a Portal URL and MAC Address.
*   **Merge Playlist**: Import channels from another M3U file into the current one (Append, Replace, or Deduplicate).
*   **Cloud Sync**: Save/Load playlists to a local folder synced with Google Drive/Dropbox.
*   **Save M3U**: Save changes to the current file.
*   **Save with Encoding**: Save with a specific character encoding (e.g., UTF-8, Latin-1).
*   **Restore Backup**: Revert to a previous state from an auto-generated zip backup.
*   **Close File**: Close the current playlist and clear the workspace.
*   **Export to CSV**: Export the playlist metadata to a spreadsheet-compatible format.

#### **Edit Menu**
*   **Undo/Redo**: Revert or re-apply changes.
*   **Find and Replace**: Search for text in specific fields (Name, URL, Group) and replace it.
*   **Batch Rename (Regex)**: Use Regular Expressions to rename channels in bulk.
*   **Bulk Edit Attributes**: Modify specific attributes (Group, Logo, EPG ID) for all selected channels at once.

#### **View Menu**
*   **Toggle Dark Mode**: Switch between Light and Dark themes.
*   **Toggle Grid/List View**: Switch the main view between a detailed table and a visual grid of icons.
*   **Theme Editor**: Customize the application's color palette.
*   **TV Mode Interface**: Switch to a high-contrast, large-font interface for TV usage.
*   **Theater Mode**: Open the dedicated full-screen IPTV player.

#### **Tools Menu**
*   **Deduplication**:
    *   **Find Duplicates**: Locate exact URL duplicates.
    *   **Find Name Duplicates**: Locate channels with the same name but different URLs.
    *   **Fuzzy Finder**: Find similar names (e.g., "HD" vs "FHD").
    *   **Smart Dedupe**: Auto-remove duplicates keeping the best quality entry.
*   **Organization**:
    *   **Smart Grouping**: Auto-categorize channels into Sports, Movies, etc.
    *   **Add Country Flags**: Detect countries in names and prepend flags to groups.
    *   **Channel Numbering**: Renumber channels or add prefixes.
    *   **Split Playlist**: Save each group as a separate M3U file.
    *   **Favorites Manager**: Reorder and rename favorite channels.
    *   **User-Agent Manager**: Apply User-Agents to specific groups.
    *   **Language Manager**: Customize language detection patterns.
*   **Logos**:
    *   **Scrape Missing Logos**: Search Google Images for missing icons.
    *   **Channel Logo Wizard**: Match logos from a repository URL.
*   **Diagnostics**:
    *   **Channel Statistics**: View charts of group/resolution distribution.
    *   **Check Resolutions**: Detect SD/HD/4K quality for streams.
    *   **Check Stream Latency**: Measure response time.
    *   **Stream Diagnostics**: Detailed FFprobe analysis of a stream.
    *   **Stream Bitrate Analyzer**: Measure real-time bitrate.
    *   **Live Stream Monitor**: Watch status of multiple streams.
    *   **Remove Invalid Streams**: Delete streams that failed the Health Check.
    *   **Auto-Repair**: Attempt to fix broken URLs (http/https swap).
*   **Network & Casting**:
    *   **Network Stream Scanner**: Find DLNA/UPnP devices.
    *   **Cast Manager**: Control active casting sessions.
    *   **Network Speed Test**: Test internet download speed.
*   **Utilities**:
    *   **Quick Translate**: Translate channel names.
    *   **Transcode Wizard**: Convert streams to MP4/MKV.
    *   **Schedule Recording**: Record streams at a set time.
    *   **Manage Recordings**: View and cancel pending recording tasks.
    *   **Playlist Diff Tool**: Compare two playlists.
    *   **Snapshot Gallery**: View captured video frames.
    *   **Update EPG Data**: Refresh XMLTV data.
    *   **Task Scheduler**: Automate backups and checks.
    *   **Version History**: View local Git commit history of playlist changes.
*   **Set Parental PIN**: Lock channels or groups with a PIN code.
*   **Settings**: Configure VLC path, FFmpeg path, and clear caches.

#### **Plugins Menu**
*   **Reload Plugins**: Refresh the list of available scripts from the `plugins/` folder.
*   **Open Plugins Folder**: Open the directory where custom Python scripts are stored.
*   *(Loaded Plugins)*: Custom actions defined by external scripts.

#### **Help Menu**
*   **Documentation**: Open the online documentation.
*   **Check for Updates**: Check for the latest version on GitHub.
*   **About**: View application version and credits.

### Keyboard Shortcuts

| Action | Shortcut |
| :--- | :--- |
| **New File** | `Ctrl+N` |
| **Save File** | `Ctrl+S` |
| **Close File** | `Ctrl+W` |
| **Undo** | `Ctrl+Z` |
| **Redo** | `Ctrl+Y` |
| **Find & Replace** | `Ctrl+F` |
| **Toggle View (Grid/List)** | `Ctrl+G` |
| **TV Mode** | `F10` |
| **Theater Mode** | `F11` |

#### Global Hotkeys (Background)
These shortcuts work even when the application is minimized or not in focus:
*   `Ctrl+Alt+P`: Play/Pause active stream (Preview, Theater Mode, or Cast).
*   `Ctrl+Alt+M`: Mute/Unmute audio.
*   `Ctrl+Alt+H`: Show/Hide the application window.

### Quick Actions
*   **Right-Click**: Access context menus for playing, editing, or locking channels.
*   **Drag & Drop**: Move rows to reorder channels (in Table View).
*   **Double-Click**: Edit a cell directly or play a stream (depending on column).

### CLI Usage

You can also launch the editor with a file directly:
```bash
python m3u_editor.py "path/to/playlist.m3u"
```


## Security & Privacy

This application prioritizes your security:
- **SSL Validation**: Flags insecure HTTP streams.
- **Content Verification**: Ensures streams are genuine media and not malicious scripts.
- **Local Processing**: Your playlist data stays on your machine.

## Roadmap

*   **Cloud Sync**: Integration with Google Drive/Dropbox for syncing playlists across devices.
*   **Advanced EPG**: Support for multiple EPG sources per playlist and manual channel mapping.

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Disclaimer

This software is provided "as is", without warranty of any kind. Users are responsible for ensuring they have the legal right to access the streams they use.

## Author

Created and maintained  Reach me  for more development opportunities.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

<div align="center">
    <p>
        Built with ❤️ using <a href="https://www.python.org/">Python</a> and <a href="https://riverbankcomputing.com/software/pyqt/">PyQt6</a>.
    </p>
    <p>
        <a href="buymeacoffee.com/kamalsoft"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" width="200" /></a>
    </p>
    <p>
        &copy; 2026 Open Source M3U Editor
    </p>
</div>