# RoadLink

Venus OS networking addon using kwindrem SetupHelper. **Development release v0.2: diagnostics and an isolated local vehicle AP.**

The native GUI at Settings → RoadLink shows the default WAN interface, connected USB WLAN and explicit Internet/failover/protection limits. Its vehicle-WLAN page controls the AP and its SSID and shows its local address. `/data/RoadLink/roadlink status`, `hardware` and `diagnostics` provide diagnostics.

The internal-radio AP uses WPA2/CCMP, isolated clients and a private non-overlapping subnet. Configure its password locally with `roadlink configure-ap` (hidden prompt) or `roadlink configure-ap --generate`. Credentials stay in a root-only file outside the package. The default temporary SSID is `breschdleng-roadlink` to avoid confusion while Starlink broadcasts a similar name. The AP is LAN-only: DHCP advertises neither an Internet gateway nor a DNS server. Internet forwarding is blocked for IPv4/IPv6. Official Venus `hostapd` and `dnsmasq`, including `hostapd_cli`, must be installed for this development release; setup does not yet provision missing dependencies.

SetupHelper package: `RoadLink`, GitHub user `CoYoDuDe`, branch `main`. Setup installs a bounded-log status service and patches the native GUI menu. Uninstall removes the service and its own menu entry, preserving other addon menus. Classic GUI/Remote Console is supported; GUI v2 integration is not implemented yet.

The source also contains stable per-profile MAC derivation, WAN selection policy and durable file-change journals. These are foundations, not an active network controller. File rollback alone does not provide network recovery.

An independent AP guard cleans up owned processes, interface and firewall rules if the controller exits or its heartbeat stalls. Setup waits for this cleanup before installation/removal. `roadlink safe-mode` disables AP activation while preserving Ethernet. This AP-specific guard is not yet full WAN recovery.

Pending: WLAN profile management in the GUI, AP password editing in the GUI, known-WLAN automatic connections, Ethernet/WLAN switching, DNSmith/WireGuard enforcement, captive portals, client management and complete UI. No bandwidth bonding is active. Never interpret link carrier or the default route as a successful Internet/security check.

Tests stay outside this repository and device packages. See `docs/ARCHITECTURE.md` for integration constraints.
