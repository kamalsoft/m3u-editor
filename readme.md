# Open Source M3U Editor

A robust, cross-platform GUI application built with Python and PyQt6 for managing, editing, and organizing M3U/M3U8 playlists. Optimized for performance and security.

## Features

*   **Playlist Management**: Load and save M3U playlists with support for standard `#EXTINF` metadata (Group, Logo, Name, Duration).
*   **Load from URL**: Download and edit playlists directly from a web link with a dedicated **Reload** button for quick refreshes.
*   **Performance Optimized**:
    *   **Fast Parsing**: High-performance M3U parser for near-instant loading of large playlists.
    *   **Efficient Undo/Redo**: Delta-based undo system reduces memory overhead.
    *   **Throttled Logo Loading**: Background logo fetching with targeted UI updates for smooth scrolling.
*   **Enhanced Stream Preview**:
    *   **Live Playback**: Interactive video preview with full playback controls (Play/Pause, Stop, Volume, Fullscreen).
    *   **Navigation**: Browse through channels directly within the preview window using Next/Previous buttons.
    *   **Integrated Storyboard**: Generate and view frame-by-frame storyboards of your streams.
    *   **Live Editing**: Edit the channel's group directly from the preview screen with real-time synchronization.
*   **Stream Security Audit**:
    *   **Comprehensive Scanning**: Audit streams for SSL/TLS validity, content-type correctness, and suspicious redirects.
    *   **Reputation Check**: Identify streams from known malicious or low-reputation domains.
    *   **Visual Indicators**: Color-coded security status (Green Shield for secure, Warning for insecure) with detailed tooltips.
*   **Smart Organization**:
    *   **Advanced Smart Grouping**: Regex-based categorization with resolution (4K, HD, SD) and country detection.
    *   **Manage Groups**: Dedicated dialog to bulk rename, add, or delete groups across the entire playlist.
    *   **Drag and Drop**: Reorder channels easily by dragging rows.
    *   **Context Menu**: Quick "Edit Group" and "Open in VLC" actions.
*   **Health Check**: Validate stream URLs via asynchronous HTTP HEAD requests with granular feedback.
*   **Search & Filter**: Real-time search and group-based filtering.
*   **Export**: Export playlists to CSV format.
*   **Dark Mode**: Sleek, modern dark theme for reduced eye strain.

## Demo

<!-- ![M3U Editor Demo](m3u-editor-demo.gif) -->
*Visual overview of the application features.*

## Prerequisites

*   Python 3.x
*   PyQt6
*   VLC (Optional, for external playback)

## Installation

1.  Clone the repository or download the source code.
2.  Install the required dependencies:

```bash
pip install PyQt6
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

## Security & Privacy

This application prioritizes your security:
- **SSL Validation**: Flags insecure HTTP streams.
- **Content Verification**: Ensures streams are genuine media and not malicious scripts.
- **Local Processing**: Your playlist data stays on your machine.

## Roadmap

*   **EPG (Electronic Program Guide) Integration**: Support for XMLTV files to display "Now Playing" information and full program schedules.
*   **Xtream Codes API Support**: Direct login support for IPTV providers using Xtream Codes credentials for automatic playlist and EPG updates.
*   **Advanced Playlist Deduplication & Merging**: A smart wizard to combine multiple playlists, intelligently detect duplicates, and manage stream sources.
*   **Favorites System**: Quick access to frequently used channels with a dedicated "Favorites" group.
*   **Batch Rename & Find/Replace**: Advanced regex-based tools for bulk channel name and metadata editing.

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