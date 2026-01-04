# Open Source M3U Editor

A robust, cross-platform GUI application built with Python and PyQt6 for managing, editing, and organizing M3U/M3U8 playlists.

## Features

*   **Playlist Management**: Load and save M3U playlists with support for standard `#EXTINF` metadata (Group, Logo, Name, Duration).
*   **Load from URL**: Download and edit playlists directly from a web link.
*   **Channel Editor**: Edit channel names, groups, logos, and stream URLs in a dedicated side panel.
*   **Organization**:
    *   **Drag and Drop**: Reorder channels easily by dragging rows.
    *   **Move Up/Down**: dedicated buttons for precise reordering.
    *   **Bulk Edit**: Select multiple rows to batch update the "Group" title.
*   **Stream Validation**:
    *   **Health Check**: Validates stream URLs via asynchronous HTTP HEAD requests.
    *   **Visual Feedback**: Rows turn Green (Valid) or Red (Invalid).
    *   **Cleanup**: "Remove Invalid" button to automatically delete dead streams.
*   **Duplicate Finder**: Identify and highlight channels with duplicate URLs.
*   **Video Preview**: Integrated video player to preview streams directly within the app (supports formats supported by the OS backend).
*   **External Player**: Open streams in VLC via right-click context menu.
*   **Search & Filter**: 
    *   Real-time filter bar to find channels by name.
    *   Dropdown menu to filter by specific groups.
*   **Undo/Redo**: Revert accidental changes using `Ctrl+Z` and re-apply them with `Ctrl+Y`.
*   **Export**: Export your playlist to CSV format for external analysis.
*   **Dark Mode**: Toggle between Light and Dark themes.

## Demo

<!-- ![M3U Editor Demo](m3u-editor-demo.gif) -->
*Visual overview of the application features.*

## Prerequisites

*   Python 3.x
*   PyQt6

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
    *   Click **Load M3U** to open a local playlist file.
    *   Click **Load URL** to import a playlist from a web address.
3.  **Edit**: Select a channel to modify its details in the right panel. Changes are reflected immediately.
4.  **Organize**: Use the "Organize" buttons or drag-and-drop to rearrange channels.
5.  **Filter**: Use the search bar or the Group dropdown to find specific channels.
6.  **Validate**: Click **Check Stream Health** to verify URLs. Once finished, you can use **Remove Invalid** to clean up.
7.  **Play**: 
    *   Use the built-in preview panel.
    *   Right-click a row and select **Open in VLC** (configure VLC path in **Settings**).
8.  **Save**: Click **Save M3U** to write your changes to a file.

## Roadmap

*   **Batch Rename**: Regex-based search and replace for channel names.
*   **Favorites**: Quick access to frequently used channels.
*   **EPG Integration**: Support for XMLTV files to show program guides.
*   **Xtream Codes**: Login support for IPTV providers.

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

## Author

Created and maintained by Kamal. Reach me at kamalsoft@gmail.com for more development opportunities.

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## Fair Usage Policy

This tool is designed for managing personal M3U playlists. Users are responsible for ensuring they have the legal right to access and use the streams contained within their playlists. The developers of this application do not endorse or support copyright infringement or the use of illegal IPTV services. Please respect content creators and rights holders.

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