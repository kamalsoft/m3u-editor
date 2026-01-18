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
*   **Smart Grouping**: Regex-based auto-categorization (Sports, Movies, News, etc.) with resolution and country detection.
*   **Channel Numbering**: Wizard to renumber channels, sort by group, and apply prefixes.
*   **Find & Replace**: Advanced search with Regular Expression support.
*   **Playlist Diff**: Compare the current playlist with another file to identify added, removed, or modified channels.
*   **Deduplication**:
    *   **Find Duplicates**: Identify and highlight or batch delete duplicate URLs.
    *   **Smart Dedupe**: Intelligent removal keeping the entry with the highest resolution or most metadata.
*   **Logo Tools**:
    *   **Scraper**: Find missing logos via Google Images.
    *   **Wizard**: Match logos from a repository URL.
*   **Country Flags**: Auto-detect country from channel names and append flags to group titles.

### 📺 Playback & Preview
*   **Stream Preview**: Live video preview with playback controls, aspect ratio, speed control, and audio/subtitle track selection.
*   **IPTV Player Mode**: Dedicated full-screen interface with channel list, search, and **Picture-in-Picture (PiP)** support.
*   **Storyboard**: Generate frame-by-frame visual storyboards of streams.
*   **Snapshot Gallery**: View, manage, and export captured snapshots.
*   **Casting**:
    *   **Chromecast/DLNA**: Cast streams to devices on your network.
    *   **Cast Manager**: Control volume, seek, stop, and manage a **Cast Queue** for continuous playback.
    *   **Remote Control**: Dockable widget and Status Bar Mini-Player for quick cast control.
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
*   **EPG Integration**: Load XMLTV EPGs (supports .gz/.xz), cache locally, and view program schedules.
*   **Task Scheduler**: Automate backups, EPG updates, and playlist validation.
*   **Plugin System**: Extend functionality with external Python scripts.

### 🎨 UI & Customization
*   **Theme Editor**: Customize application colors and save themes.
*   **Dark Mode**: Built-in dark theme for reduced eye strain.
*   **Quick Access Toolbar**: Pin your favorite actions for easy access.
*   **Global Search**: Filter playlist by Name, Group, URL, or EPG ID.
*   **Virtual List View**: Efficient handling of large playlists (10k+ channels).

## Demo

*Visual overview of the application features.*

## Prerequisites

*   Python 3.x
*   PyQt6
*   **FFmpeg/ffprobe**: Required for Resolution Checker, Diagnostics, Transcoding, and Recording.
*   **pychromecast**: Required for Casting features.
*   **VLC**: Optional, for external playback.

## Installation

1.  Clone the repository or download the source code.
2.  Install the required dependencies:

```bash
pip install PyQt6 pychromecast
```

*Note: Depending on your OS, you might need additional codecs for the video preview to work with all stream types.*

## Usage

1.  **Run the application**:
    ```bash
    python m3u_editor.py
    ```
2.  **Load**: 
    *   Click **Load M3U** for local files or **Load URL** for web playlists.
    *   Use the **Reload** button to refresh the current source.
3.  **Edit**: Select a channel to modify its details in the right panel, or edit the **Group** directly in the **Stream Preview**.
4.  **Security Audit**: Click **Security Audit** in the toolbar to scan selected or all streams for potential threats.
5.  **Smart Grouping**: Use the **Smart Grouping** feature to automatically categorize channels based on their names.
6.  **Manage Groups**: Use the **Manage Groups** button to perform bulk group operations.
7.  **Save**: Click the **Save** button (enabled when changes are made to local files) to persist your work. Modified files are marked with an asterisk (*) in the title bar.
8.  **Settings**: Configure VLC path and clear local EPG cache via the **Tools > Settings** menu.


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