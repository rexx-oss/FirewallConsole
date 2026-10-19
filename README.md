# FirewallConsole

Portable Windows Firewall manager built on .NET 10 using direct COM interop (`HNetCfg.FwPolicy2`).

## Key Features

* Enforced Whitelist: Sets default outbound traffic to Block across all network profiles and disables unauthorized Allow rules while preserving Windows Core Networking.
* Reversible State: Switching to Blacklist mode restores default-allow and re-enables all auto-suppressed rules.
* Live WFP Drop Monitor: Captures blocked connection attempts (Event 5157) in real time with an on/off toggle. Double-clicking any dropped entry creates a rule for that executable.
* Drag-and-Drop Rules: Drop any `.exe` onto the window to auto-populate a new rule.
* Machine Migration: Saves full rule schemas in `firecon.ini`. Moving the application folder to another PC automatically provisions the rules into that machine's Windows Firewall.

## Usage

1. Run `firecon.exe` as Administrator.
2. Select Whitelist (default-deny outbound) or Blacklist (default-allow).
3. Create rules by dropping an executable onto the window, or monitor the Blocked Connections tab and double-click dropped apps to authorize them.
4. To replicate rules on another PC, copy the folder containing `firecon.exe` and `firecon.ini`.
