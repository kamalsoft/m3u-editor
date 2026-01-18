from PyQt6.QtWidgets import QMessageBox

PLUGIN_NAME = "Hello World"

def run(window):
    """
    Entry point for the plugin.
    'window' is the main M3UEditorWindow instance.
    """
    # 1. Access data from the main window
    channel_count = len(window.entries)
    
    # 2. Show a message box using the main window as parent
    QMessageBox.information(window, "Hello World Plugin", 
                            f"Hello! This is an external plugin.\n\n"
                            f"Current Playlist Size: {channel_count} channels.\n"
                            f"Active File: {window.current_file_path or 'Unsaved/URL'}")
    
    # 3. Interact with main window methods
    if hasattr(window, 'log_action'):
        window.log_action("Hello World plugin executed successfully.")
        
    # 4. Example: Modify status bar
    window.status_label.setText(f"Hello World Plugin says hi! ({channel_count} channels)")