# Network integration findings

Observed on a Raspberry Pi 4 running Venus OS v3.81, 2026-10-06.

- Venus owns ConnMan 1.33, the system wpa_supplicant and a loopback-only dnsmasq 2.90. ConnMan stores profiles under `/data/var/lib/connman`.
- The stock Raspberry Pi image lacked hostapd and its Venus service template. Official Venus packages hostapd 2.10 and wireguard-tools were installed for development. RoadLink runs a protected AP on its own ConnMan-excluded virtual interface and a guarded WireGuard tunnel to DNSmith. A WireGuard kernel module is already packaged.
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

Hardware discovery, WAN selection policy, MAC derivation and a file journal exist. A DBus service, CLI, classic native GUI and isolated AP have passed install/uninstall/reinstall on the Pi. AP startup checks hostapd's ENABLED state before reporting availability. A separate guard owns cleanup and holds the runtime lock through cleanup; failed cleanup prevents a new AP or installation/removal. AP ingress uses table 51900, priority 21900, with a WireGuard default and unreachable fallback. Device VPN probes use table 51890, priority 21890. AP forwarding permits only valid AP-subnet traffic to WireGuard and established return traffic; source NAT uses the enrolled VPN client address. AP rules redirect ordinary DNS to DNSmith and block DoT and private/reserved routed destinations. Native management/default routes remain unchanged. AP guard cleanup removes the AP interface before its routing and rules. VPN cleanup removes WireGuard; the AP unreachable route and drops remain. VPN FORWARD drops exclude the AP pair because the AP controller owns its constrained rules, preserving those rules across VPN restarts. IPv6 remains blocked. Arbitrary DoH filtering, external-WLAN identity enforcement, WAN switching, captive portal assistant, client manager, web UI and GUI v2 integration remain pending. Passing local policy tests does not verify any live security property.

References: [SetupHelper guidelines](https://github.com/kwindrem/SetupHelper/blob/main/PackageDevelopmentGuidelines.md), [Venus platform](https://github.com/victronenergy/venus-platform), [Venus package recipes](https://github.com/victronenergy/meta-victronenergy).

## v0.8 packet verification

A disposable Linux namespace client exercised the production AP routing/firewall builders on a separate veth ingress and reserved test table. Its redirected DNS and verified HTTPS worked through the VPN with the server public address. Private-network and DoT probes failed. Removing the VPN default left the unreachable fallback; deliberately removing the test policy also failed because the AP base drop caught Ethernet-bound traffic. The test namespace, rules, interface and table were removed, and the native Ethernet default remained unchanged. This verifies routed packets, not wireless radio performance or phone connectivity. Production lifecycle/crash and SetupHelper verification are recorded separately in device diagnostics. Tests are kept outside the package/repository.
