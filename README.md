# RoadLink

Work in progress for Venus OS and kwindrem SetupHelper. Not yet a deployable network controller.

The current local source contains read-only hardware discovery, stable per-profile WAN MAC derivation and WAN selection policy. No network changes or firewall protections are active merely because these sources exist.

The implementation will reuse Venus ConnMan and its existing DNS/AP architecture where available. It must preserve local recovery access and prove rollback, firewall isolation and DNS/VPN fail-closed behavior before enabling routing on a real vehicle.

Development tests live outside this repository and are excluded from device packages.
