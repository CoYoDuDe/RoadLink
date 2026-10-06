# RoadLink

Venus OS networking addon using kwindrem SetupHelper. **Development release v0.1: network diagnostics only.**

The native GUI at Settings → RoadLink and `/data/RoadLink/roadlink status` show live hardware roles and the default interface. `hardware` also reports radio capabilities; `diagnostics` returns the current status as JSON. No routing, automatic association, AP or VPN protection is activated by this release.

SetupHelper package: `RoadLink`, GitHub user `CoYoDuDe`, branch `main`. Setup installs a bounded-log status service and patches the native GUI menu. Uninstall removes the service and its own menu entry, preserving other addon menus. Classic GUI/Remote Console is supported; GUI v2 integration is not implemented yet.

The source also contains stable per-profile MAC derivation, WAN selection policy and durable file-change journals. These are foundations, not an active network controller. File rollback alone does not provide network recovery.

Pending: network recovery/watchdog, AP, known-WLAN automatic connections, Ethernet/WLAN switching, DNSmith/WireGuard enforcement, captive portals, client management and complete UI. Never interpret link carrier or the default route as a successful Internet/security check.

Tests stay outside this repository and device packages. See `docs/ARCHITECTURE.md` for integration constraints.
