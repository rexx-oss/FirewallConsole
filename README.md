# FirewallConsole

Native Windows Firewall management and monitoring console built on .NET 10. Uses direct Windows COM interop (HNetCfg.FwPolicy2) for near-zero CPU and ~25 MB RAM footprint. Fully portable with single-file INI storage.

## Features

* Whitelist Mode: Sets default outbound policy to Block across all network profiles. Auto-disables all non-approved Allow rules while retaining Windows Core Networking.
* Blacklist Mode: Sets default outbound policy to Allow and restores previously auto-suppressed rules.
* Drop Monitor: Captures real-time WFP blocked connections (Security Event 5157). Includes a Start/Stop toggle to prevent log flooding and save resources.
* Quick Rule Creation: Drag and drop any .exe into the window, or double-click any blocked connection in the monitor to generate a rule.
* Full-Row Controls: Read-only DataGrid prevents accidental cell typing. Double-click any rule row to edit its parameters in a modal dialog.
* Batch Operations: Single-click toggles for Enable/Disable and Allow/Block across multiple highlighted rules.
* Collision-Proof Hashing: Uses 16-character SHA-256 fingerprints to identify rules, avoiding name collisions and INI corruption.
* Portable Sync: Saves custom and approved rules in firecon.ini. Moving the folder to a new machine auto-provisions stored rules on startup.
* Tray Integration: Closes or minimizes to system tray with Start Minimized option and background watchdog. Light and Dark themes included.

## How to Use

1. Run firecon.exe as Administrator.
2. Select an operating mode:
   * Whitelist (Strict): Default-deny. Only approved rules and Core Networking can connect out.
   * Blacklist (Permissive): Default-allow. Standard Windows behavior.
3. Manage rules in Outbound or Inbound tabs:
   * Click Approve to whitelist an Allow rule so it stays active.
   * Click Enable/Disable or Allow/Block to toggle selected rows.
   * Double-click a row to edit port, protocol, path, or profile settings.
4. Add rules:
   * Click New Rule, or drag and drop an executable file anywhere onto the window.
5. Capture blocked apps:
   * Go to the Blocked Connections tab and click Start Logging.
   * Double-click any logged blocked app to open a pre-filled rule dialog.
   * Click Stop Logging when finished to release monitor resources.
6. Migrate to a new PC:
   * Copy the application folder containing firecon.exe and firecon.ini to the new PC. Run it as Administrator; all saved rules will be restored automatically.

## Configuration (firecon.ini)

All settings, approvals, and rule backups reside in firecon.ini alongside the executable:

* [Settings]: Stores Theme, Mode (Whitelist/Blacklist), and StartMinimized states.
* [ApprovedRules]: Stores rule ID approval keys.
* [Rule_<ID>]: Full parameter backup for each managed rule.
* [AutoDisabled]: Tracks rules suppressed by Whitelist mode for clean restoration.
