# Network integration findings

Observed on a Raspberry Pi 4 running Venus OS v3.81, 2026-10-06.

- Venus owns ConnMan 1.33, the system wpa_supplicant and a loopback-only dnsmasq 2.90. ConnMan stores profiles under `/data/var/lib/connman`.
- This Raspberry Pi image has no hostapd binary or Venus hostapd service template installed. The official Venus package feed provides hostapd 2.10 and wireguard-tools. A WireGuard kernel module is already packaged.
- Other Venus boards use `ap0`, a hostapd service template, and a dedicated AP configuration of the Venus dnsmasq package. `venus-platform` exposes AP controls only when the service template exists.
- ConnMan excludes names beginning with `ap`, `disabled` and `ll`. This is relevant to single ownership of AP interfaces.
- The internal brcmfmac radio supports AP mode. The external MT7612U/mt76x2u radio supports managed and AP modes with two transmit/receive chains. Its serial number is all zeroes and cannot identify a unique adapter; discovery falls back to its USB topology.
- Local Ethernet is the recovery path. Its default gateway must not be removed merely to test wireless features.

## Boundaries

RoadLink must not start a second competing station/DHCP service on an interface already owned by Venus. Native AP primitives should be reused where available. Before enabling any external Wi-Fi association, verify that per-profile MAC, DHCP identity and IPv6/discovery restrictions can actually be enforced by the selected backend. Unsupported privacy controls must be reported, not claimed as active.

Root-owned persistent configuration belongs outside the replaceable `/data/RoadLink` package directory. Runtime files belong under `/run`. Services and bounded logs use SetupHelper's service directory convention. Native menu files use FileSets/PatchSource and are reverse-patched at uninstall.

## Recovery

`transactions.py` currently implements only durable, allowlisted file changes, confirmation deadlines and recovery after a changed boot ID. Concurrent edits are preserved as a conflict. It is not yet a complete network rollback implementation: process locking, an independent watchdog, runtime route/firewall/interface restoration and live reachability checks remain required.

## Current implementation limits

Only hardware discovery, WAN selection policy, MAC derivation and the file journal exist. There is no deployed AP, routing backend, VPN, DNS enforcement, captive portal assistant, client manager, web UI or native RoadLink GUI yet. Passing local policy tests does not verify any live security property.

References: [SetupHelper guidelines](https://github.com/kwindrem/SetupHelper/blob/main/PackageDevelopmentGuidelines.md), [Venus platform](https://github.com/victronenergy/venus-platform), [Venus package recipes](https://github.com/victronenergy/meta-victronenergy).
