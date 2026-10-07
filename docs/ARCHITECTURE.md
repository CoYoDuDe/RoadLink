# RoadLink: Technik und Einrichtung

Diese Seite beschreibt den aktuellen Entwicklungsstand. Die kurze Bedienung steht in der [README](../README.md).

## VPN einrichten

Der Server braucht WireGuard, einen registrierten Client-Schlüssel, Internetweiterleitung und einen DNS-Dienst im Tunnel. RoadLink richtet den Server derzeit nicht automatisch ein.

Auf dem Venus-Gerät als root:

```sh
/data/RoadLink/roadlink vpn-public-key
```

Den ausgegebenen **öffentlichen** Schlüssel am eigenen Server registrieren. Der private Schlüssel bleibt auf dem Gerät. Anschließend die Platzhalter durch die eigenen Daten ersetzen:

```sh
/data/RoadLink/roadlink configure-vpn --endpoint PUBLIC_IPV4 --server-key PUBLIC_KEY --address CLIENT_IPV4/32 --dns VPN_DNS --enable
```

Als Serveradresse wird eine öffentliche IPv4-Adresse benötigt. Die Client-Adresse ist eine einzelne private IPv4-Adresse mit `/32`; DNS muss im Tunnel erreichbar sein. Keine fremden Zugangsdaten übernehmen.

## Fahrzeug-WLAN

Passwort verdeckt abfragen und den Standardnamen RoadLink setzen:

```sh
/data/RoadLink/roadlink configure-ap
```

Ein eigener Name ist mit `--ssid NAME` möglich. Das Fahrzeug-WLAN anschließend im Menü aktivieren. Ein neues Passwort trennt bestehende WLAN-Clients. Ohne funktionsfähigen VPN-Tunnel bleibt das WLAN lokal.

## Schutz und Wiederherstellung

Der interne Funkadapter stellt den WPA2/CCMP-Zugangspunkt bereit. Der ausgewählte USB-Adapter arbeitet allein in einem eigenen Linux-Netzwerkbereich (`roadlink-wan`). Vor dem Verbindungsaufbau werden IPv6 und unerlaubte IP-Verbindungen gesperrt. Private, pro Profil abgeleitete MAC-Adressen und reduzierte DHCP-Angaben vermeiden unnötige Geräteinformationen. Das ist keine Zusicherung von Unsichtbarkeit.

Vom Host zum USB-Netz sind nur markierte WireGuard-Pakete zum konfigurierten Server erlaubt. Die unveränderte Ethernet-Standardroute dient weiter dem Gerätezugang. Fahrzeug-WLAN-Pakete dürfen ausschließlich durch WireGuard; unerreichbare Ersatzrouten und Firewall-Regeln verhindern einen unverschlüsselten Rückfall. Normales DNS wird zum Tunnel-DNS umgeleitet, Port 853 und private/reservierte Weiterleitungsziele werden gesperrt. Eine vollständige DoH-Filterung ist noch offen.

Die Tabellen 51890 (VPN-Prüfung), 51900 (Fahrzeug-WLAN) und 51910 (verschlüsselter WAN-Transport) sind getrennt. Der Transport nutzt Markierung `0x524c`. Netzlokale Gesundheitsprüfungen dürfen nur das feste HTTPS-Ziel `1.1.1.1:443` mit geprüftem TLS-Namen erreichen; sie verwenden kein externes DNS. Internetbereitschaft braucht zusätzlich einen aktuellen WireGuard-Handshake, Tunnel-DNS und HTTPS durch den Tunnel.

Unabhängige Wächter stoppen ausgefallene Prozesse und räumen nur nachgewiesene eigene Schnittstellen, Mounts und Regeln auf. Prozesskennungen enthalten den Startzeitpunkt; Netzwerkbereiche werden anhand ihrer Inode-/Gerätekennung geprüft. Fremde oder ersetzte Ressourcen werden nicht auf Verdacht entfernt. SetupHelper wartet vor Updates und Deinstallation auf die Bereinigung. Gezielte Abbruchtests decken auch die kurzen Fenster beim Erstellen von Netzwerkbereich und Verbindungspaar ab.

## WLAN-Suche

Die passive Suche läuft in einem separat registrierten Prozess mit höchstens drei Versuchen von jeweils 40 Sekunden. Der Controller bleibt währenddessen überwacht. Rohdaten werden privat gespeichert und danach entfernt. Die Oberfläche erhält nur WLAN-Name, unterstützte Verschlüsselung, Signalstärke und Frequenz; keine Passwörter oder rohen BSSIDs. Ergebnisse gelten drei Minuten. Die Auswahl füllt zunächst nur das Formular; sie verbindet noch kein Netz.

Der Suchbetrieb ist auch ohne gespeicherte Profile oder VPN möglich. Dann gibt es keine IP-Adresse, keinen DHCP-Prozess und keine Host-Verbindung. Ohne VPN bleibt die automatische Verbindung gesperrt.

Der Schalter **Offene WLANs automatisch prüfen** ist standardmäßig aus. Bei eingeschaltetem Schalter werden echte offene Netze aus höchstens drei Minuten alten Suchergebnissen als vorübergehende Kandidaten verwendet. Gespeicherte WLANs behalten Vorrang; deaktivierte Profile und offene Varianten gespeicherter verschlüsselter SSIDs werden ausgeschlossen. Gefundene Netze werden nicht automatisch gespeichert oder als vertrauenswürdig markiert. Ihre private MAC-Adresse wird aus der lokalen Gerätekennung und Profilkennung abgeleitet.

Nach zwei fehlgeschlagenen HTTPS-Prüfungen oder einem dem aktuellen Profil zugeordneten Tunnel-Fehler wird ein Kandidat verworfen. Verbindungsaufbau ohne IP-Adresse endet nach 45 Sekunden. Wartezeiten steigen bei wiederholten Fehlern von 60 auf höchstens 900 Sekunden. Ohne brauchbaren Kandidaten wird höchstens alle 150 Sekunden eine passive Suche angefordert; laufende manuelle Suchen werden nicht ersetzt. Die Internetfreigabe bleibt an aktuellen VPN-, DNS- und Tunnel-HTTPS-Nachweis gebunden. Captive-Portal-Erkennung und Anmeldung sind noch offen.

## Diagnose

```sh
/data/RoadLink/roadlink status
/data/RoadLink/roadlink vpn-status
/data/RoadLink/roadlink ap-status
/data/RoadLink/roadlink diagnostics
```

`vpn-disable` schaltet den Tunnel aus. `safe-mode` schaltet das Fahrzeug-WLAN aus; Ethernet bleibt verfügbar. Statusdateien liegen unter `/run/roadlink-*`, private Einstellungen unter `/data/setupOptions/RoadLink` und das Dienstlog unter `/var/log/com.coyodude.roadlink/current`. Zugangsdaten und private Schlüssel nicht veröffentlichen.

Die Anpassungen verwenden [SetupHelper](https://github.com/kwindrem/SetupHelper) und seine [Paketregeln](https://github.com/kwindrem/SetupHelper/blob/main/PackageDevelopmentGuidelines.md). Gemeinsame HelperResources werden nicht verändert. Für eigene QML-Dateien bleibt die NO_ORIG-Markierung erhalten; nur inhaltsgenau nachgewiesene alte RoadLink-Kopien werden nach privater Sicherung repariert. Tests bleiben außerhalb des Pakets.
