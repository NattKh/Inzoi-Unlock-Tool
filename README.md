# Inzoi-Unlock-Tool
Rust tool for unlocking extra content 
inZOI DLC Unlocker
===============================

Overview
--------
The inZOI DLC Unlocker is a simple tool designed to patch the inZOI game executable (inZOI-Win64-Shipping.exe) to redirect its authentication and entitlement checks to a local server, unlocking DLC content. It also provides an option to launch the game with the server without patching. The tool is built for ease of use and remembers your game file location for convenience.

Features
--------
1. **Patch Non-Genuine Mode**
   - Modifies the game executable to redirect all authentication, token, and entitlement requests to a local server (127.0.0.1).
   - Automatically unlocks content via the embedded entitlements JSON.
   - Creates a backup of the original file (inZOI-Win64-Shipping.exe.bak) before patching.

2. **Patch Genuine Mode**
   - Patches only the entitlements endpoint, leaving authentication and token requests intact for a more "genuine" experience.
   - Also creates a backup before patching.

3. **Start Game & Server API**
   - Launches the game and starts the local server without modifying the executable.
   - Useful if the game is already patched or you want to test without changes.

4. **Path Persistence**
   - Saves the location of your inZOI-Win64-Shipping.exe to a config.txt file after you select it.
   - Loads the saved path on startup, so you don’t need to reselect the file each time.

5. **Simple GUI**
   - User-friendly interface with buttons for selecting the game file, patching, and launching.
   - Displays status messages (e.g., "Patching successful!" or "Launching game...").

How to Use
----------
1. **Setup**
   - Place `inzoi_tool.exe` in a convenient directory (e.g., your inZOI game folder).
   - Run the tool as an administrator (required for port 80 access).

2. **First Run**
   - Click "Select Game Binary" and choose `inZOI-Win64-Shipping.exe` from your game folder.
   - The path will be saved to `config.txt` in the same directory as the tool.

3. **Options**
   - **Patch Non-Genuine**: Patches the executable fully and launches the game with the server.
   - **Patch Genuine**: Patches only the entitlements and launches the game.
   - **Start Game & Server API**: Runs the game and server without patching.

4. **Subsequent Runs**
   - The tool loads the saved path automatically. Just click Start Game & Server API
   - To change the game file, click "Select Game Binary" again.

Requirements
------------
- Windows operating system (tested on Windows 10).
- Administrative privileges (for binding to port 80).
- inZOI game installed with access to `inZOI-Win64-Shipping.exe`.

Notes
-----
- **Backup**: The tool creates a backup (`.exe.bak`) the first time you patch. Restore it manually if needed (e.g., after a game update).
- **Game Updates**: If Steam updates the game, you may need to repatch the new executable.
- **Config File**: `config.txt` stores the path. Delete it to reset the saved location.
- **Errors**: If patching fails, check the status message and restore from the backup if necessary.

Disclaimer
----------
This tool is for educational purposes only. Use it at your own risk. Modifying game files may violate the game’s terms of service. The author is not responsible for any consequences of using this software.

credits
-------
Thank you to Sorrow at cs.rin for providing src. I just piggyback off his code to provide a streamline process.

Happy gaming!
