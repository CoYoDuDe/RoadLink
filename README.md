# RoadLink

Venus OS networking addon using kwindrem SetupHelper. **Development release v0.5: local AP and native external-WLAN profile management with direct editing.**

The native GUI at Settings → RoadLink shows the default WAN interface, connected USB WLAN and explicit Internet/failover/protection limits. Its vehicle-WLAN page controls the AP and its SSID and shows its local address. `/data/RoadLink/roadlink status`, `hardware` and `diagnostics` provide diagnostics.

The internal-radio AP uses WPA2/CCMP, isolated clients and a private non-overlapping subnet. Configure its password locally with `roadlink configure-ap` (hidden prompt) or `roadlink configure-ap --generate`. Credentials stay in a root-only file outside the package. The default temporary SSID is `breschdleng-roadlink` to avoid confusion while Starlink broadcasts a similar name. The AP is LAN-only: DHCP advertises neither an Internet gateway nor a DNS server. Internet forwarding is blocked for IPv4/IPv6. Official Venus `hostapd` and `dnsmasq`, including `hostapd_cli`, must be installed for this development release; setup does not yet provision missing dependencies.

SetupHelper package: `RoadLink`, GitHub user `CoYoDuDe`, branch `main`. Setup installs a bounded-log status service and patches the native GUI menu. Uninstall removes the service and its own menu entry, preserving other addon menus. Classic GUI/Remote Console is supported; GUI v2 integration is not implemented yet.

The source also contains stable per-profile MAC derivation, WAN selection policy and durable file-change journals. These are foundations, not an active network controller. File rollback alone does not provide network recovery.

An independent AP guard cleans up owned processes, interface and firewall rules if the controller exits or its heartbeat stalls. Setup waits for this cleanup before installation/removal. `roadlink safe-mode` disables AP activation while preserving Ethernet. This AP-specific guard is not yet full WAN recovery.

The vehicle-WLAN page includes masked password entry (8–63 printable ASCII characters). Saving restarts the vehicle AP and disconnects its clients. The write-only password BusItem never publishes its submitted value through GetValue, GetItems or change signals; only a result status is exposed. The existing password is never shown. Native Ethernet settings remain available for recovery. Native Wi-Fi settings remain unchanged until RoadLink can safely take full ownership of external WLAN management.

External-WLAN profiles can be added by SSID, listed and forgotten in RoadLink's native GUI. Profiles include WPA/WPA2 or open security, priority 0–100 and the intended autoconnect setting. Resaving the same SSID/security updates it; leaving the password blank preserves an existing password. Enter the password after selecting the SSID/security, then save within 60 seconds. Password inputs stay write-only and expire from memory. Profiles persist privately outside the package, with a stable derived MAC assigned per profile and VPN required. These are stored settings: automatic association and MAC/VPN enforcement are not yet active. The GUI explicitly reports this limitation. CLI commands `wifi-list`, `wifi-save --ssid NAME` and `wifi-forget --id ID` use the same store; passwords use a hidden prompt.

The saved-WLAN list includes a new-profile entry. Open a profile and select Edit to load its SSID/security/priority/autoconnect settings. Saving edits preserves its identity and private MAC when renaming; leaving the password field untouched retains the existing password. Duplicate SSID/security combinations are rejected. Larger priority values appear first. Measured automatic ranking and phone import/export are not implemented yet.

Pending: WLAN scan-and-select, measured network ranking, portable import/export, known-WLAN automatic connections, Ethernet/WLAN switching, DNSmith/WireGuard enforcement, captive portals, client management and complete UI. No bandwidth bonding is active. Never interpret link carrier or the default route as a successful Internet/security check.

Tests stay outside this repository and device packages. See `docs/ARCHITECTURE.md` for integration constraints.
