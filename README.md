# RoadLink

Internet und eigenes Fahrzeug-WLAN für Venus OS auf dem Raspberry Pi.
**Entwicklungsstand v0.20 – noch keine fertige Endversion.**

## Installation

[SetupHelper von kwindrem](https://github.com/kwindrem/SetupHelper) installieren. Im Paketmanager eintragen:

- Paket: `RoadLink`
- GitHub-Benutzer: `CoYoDuDe`
- Branch: `main`

Danach **Einstellungen → RoadLink** öffnen. Benötigt werden die Venus-Pakete `hostapd`, `dnsmasq` und WireGuard. Fehlende Abhängigkeiten werden derzeit noch nicht automatisch installiert.

Die Startseite zeigt den Internetpfad, das verbundene WLAN und den Status. Unter **Fahrzeug-WLAN**, **Externe WLANs**, **Internet und Umschaltung** und **Diagnose** liegen die jeweiligen Einstellungen.

## Erste Einrichtung

1. Internet über Ethernet bereitstellen oder USB-WLAN-Reserve einschalten und ein externes WLAN speichern.
2. Für das Fahrzeug-WLAN ein eigenes Passwort festlegen und es einschalten.
3. DNSmith richtet den VPN automatisch ein, sobald Internet erreichbar ist. Unter **Internet und Umschaltung** stehen Schalter und Einrichtungsstatus. Vorhandene VPN-Einstellungen werden nicht überschrieben.
4. Ein externes WLAN auswählen und speichern. Automatische Verbindung im gewünschten Profil freigeben.

Das Fahrzeug-WLAN heißt bei Neuinstallation **RoadLink**. Es gibt kein gemeinsames WLAN-Passwort und keine vorgegebenen externen WLANs oder gemeinsamen VPN-Schlüssel. WLAN und USB-Reserve starten ausgeschaltet; der Verbindungsmodus ist `AUTO`. DNSmith-Einrichtung startet eingeschaltet. Bestehende Einstellungen bleiben bei Updates erhalten.

## Was bereits funktioniert

- Eigenes Fahrzeug-WLAN mit WPA2 und getrennten WLAN-Clients.
- Automatische kostenlose DNSmith-VPN-Einrichtung ohne Konto. Jeder Pi erzeugt seinen eigenen Schlüssel; der private Schlüssel bleibt auf dem Gerät. Die Erstverbindung über USB-WLAN erlaubt ausschließlich DHCP und die festgelegten HTTPS-Ziele für Einrichtung und Internetprüfung. Fahrzeuggeräte erhalten dabei noch keinen Internetzugang.
- Unter **Internet und Umschaltung → VPN-Anbieter** zwischen DNSmith und eigenem WireGuard-Server wechseln. Beide Konfigurationen bleiben lokal gespeichert. Für den eigenen Server den angezeigten Geräte-Public-Key dort registrieren und Serveradresse, Port, Server-Public-Key, Clientadresse und VPN-DNS eintragen.
- Externe WLANs suchen, hinzufügen, bearbeiten und entfernen; WPA2 oder offen.
- Gespeicherte, freigegebene WLANs automatisch verbinden; Priorität selbst festlegen.
- Optional unbekannte offene WLANs automatisch suchen und prüfen. Der Schalter startet ausgeschaltet. Erst nach bestätigtem Internet und DNS über dieses WLAN wird es gespeichert; bei eingeschaltetem VPN muss auch der Tunnel funktionieren. Fehlgeschlagene Netze werden mit Wartezeit erneut geprüft.
- Profile als letzte Reserve markieren. Sie bleiben bei funktionierendem Ethernet getrennt; normale bekannte oder gefundene offene Netze erhalten Vorrang. Innerhalb der Gruppe entscheidet die Priorität. „Nur WLAN“ erlaubt die Reserve auch bei gesundem Ethernet.
- Optionalen Gerätenamen für externe WLANs einstellen; leer sendet keinen DHCP-Namen. Der Betreiber kann eine eigene Bezeichnung anzeigen. Der Fahrzeug-WLAN-Name ist unabhängig davon.
- Ethernet/Starlink oder USB-WLAN für den verschlüsselten VPN-Tunnel wählen.
- Aktives Netz, verbundenes WLAN und geprüften Internet-/DNS-Status im klassischen Venus-Menü sehen.
- Automatische Umschaltung bei Ausfall mit verzögerter Rückkehr, damit die Verbindung nicht ständig wechselt.

**Standardmäßig erhält das Fahrzeug-WLAN Internet über den geprüften VPN-Tunnel.** Ein direkter Betrieb muss ausdrücklich gewählt werden. Eine WLAN-Verbindung oder IP-Adresse allein reicht nicht. Ethernet und SSH für den Gerätezugang bleiben erhalten. WLAN-Betreiber können weiterhin einen verbundenen Teilnehmer erkennen; RoadLink macht ihn nicht unsichtbar.

## Verbindungsmodi

### Fahrzeugnetz und VPN

Der Pi vergibt im Fahrzeug-WLAN eigene IP-Adressen per DHCP. Das externe WLAN wird nicht mit dem Fahrzeugnetz verbunden. Die Firewall sperrt neue Zugriffe von außen; der WLAN-Betreiber sieht keine einzelnen Fahrzeuggeräte als eigene WLAN- oder DHCP-Clients. Einen verbundenen Pi und dessen Verkehr kann er weiterhin erkennen.

Der VPN-Tunnel führt vom Pi zu einem externen WireGuard-Server. DNSmith ist der Standardanbieter und stellt jedem automatisch eingerichteten Gerät einen eigenen Zugang bereit. Der Server sperrt Verbindungen zu anderen VPN-Teilnehmern, privaten Netzen und seinen Verwaltungsdiensten. Ein rein lokaler VPN auf dem Pi ersetzt diese Gegenstelle nicht.

**DNSmith-VPN** ist standardmäßig ausgewählt. Ausschalten wählt einen eigenen WireGuard-Server und zeigt dessen Felder. Ohne gespeicherte eigene Konfiguration bleibt das Fahrzeug-Internet gesperrt. Zurückschalten stellt die DNSmith-Konfiguration wieder her; bei einem neuen Gerät wird sie automatisch eingerichtet. **DNSmith automatisch einrichten** steuert nur die Registrierung und beendet keinen vorhandenen Tunnel.

Unter **Internet und Umschaltung → DNS-Anbieter** ist **DNSmith-DNS** standardmäßig eingeschaltet. Ausschalten zeigt die Felder für einen eigenen öffentlichen IPv4-DNS und einen optionalen zweiten DNS. Neue Adressen erst speichern; bis dahin bleibt der bisherige Anbieter aktiv. Beide DNS-Adressen werden über den gewählten Internetpfad geprüft. Antwortet der erste nicht, wird der zweite verwendet. Beim Wechsel aktualisiert RoadLink Firewall und DHCP; im VPN-Betrieb startet dazu das Fahrzeug-WLAN neu. Ohne erreichbaren DNS wird kein Internet als bereit angezeigt. Zurückschalten erhält die eigenen gespeicherten Adressen.

Die DNS-Auswahl gilt unabhängig vom VPN-Anbieter. Mit DNSmith-VPN wird der interne DNSmith-Resolver verwendet; mit einem anderen VPN wird DNSmith über seine öffentliche Adresse erreicht. Der Profil-DNS im eigenen VPN bleibt als ursprüngliche Serverangabe gespeichert; den tatsächlich verwendeten DNS legt das Menü **DNS-Anbieter** fest.

Unter **Internet und Umschaltung** ist **Internet über VPN** standardmäßig eingeschaltet. Ausschalten wählt ausdrücklich den direkten Betrieb. Eigene IP-Vergabe, NAT und Firewall trennen weiterhin das Fahrzeugnetz vom externen WLAN. Ohne VPN entfallen die Tunnelverschlüsselung und dessen DNS-Schutz; DNS wird direkt an den gewählten öffentlichen Resolver gesendet. HTTPS bleibt durch die jeweilige Anwendung verschlüsselt.

Beim Wechsel beendet RoadLink zunächst den bisherigen Modus und prüft dessen Bereinigung. Erst danach startet der gewählte Modus. VPN-Profile und Schlüssel bleiben gespeichert. Scheitert die Bereinigung, startet der neue Modus nicht. Ein VPN-Ausfall schaltet niemals automatisch auf unverschlüsselten Betrieb um. Bei DNSmith-DNS verwendet der direkte Betrieb dessen öffentliche Adresse; eigene primäre und sekundäre DNS-Adressen bleiben unabhängig einstellbar.

| Modus | Verhalten |
|---|---|
| AUTO | Ethernet bevorzugen, bei Ausfall geeignetes WLAN nutzen |
| PREFER_STARLINK | Ethernet/Starlink bevorzugen |
| PREFER_WIFI | Geeignetes WLAN bevorzugen |
| BEST_CONNECTION | Aktuell die Antwortzeit vergleichen |
| STARLINK_ONLY | Nur Ethernet/Starlink verwenden |
| WIFI_ONLY | Nur USB-WLAN verwenden |

## Noch offen

WLAN-Anmeldeseiten, Geschwindigkeitsmessung und gelerntes Ranking, echte Bündelung/Beschleunigung, Handy-Import, Clientverwaltung sowie Weboberfläche/GUI v2. Ein WLAN ohne nutzbaren Internet-/VPN-Zugang wird derzeit verworfen; eine Anmeldeseite wird noch nicht geöffnet. HTTPS-basierte Fremd-DNS-Dienste werden noch nicht vollständig gefiltert. Die aktuelle Oberfläche unterstützt das klassische Venus-GUI und die Remote Console.

## Updates und Entfernen

Updates und Deinstallation laufen über SetupHelper. Eigene Zugangsdaten und Schlüssel liegen ausschließlich lokal unter `/data/setupOptions/RoadLink`, außerhalb des Pakets. Nach dem ersten Anbieterwechsel liegen die VPN-Konfigurationen in `wireguard/providers.json`; eine vorhandene `wireguard/config.json` bleibt unverändert als Ausgangskonfiguration erhalten. Nach einer Deinstallation bleiben sie für eine spätere Neuinstallation erhalten. Tests sind kein Bestandteil des veröffentlichten Pakets.

## Unterstützung

RoadLink ist kostenlos. Standard für VPN und DNS ist [DNSmith.net](https://dnsmith.net/setup/#roadlink); die automatische Einrichtung benötigt kein Konto und keine Spende.

Mit einer freiwilligen Spende unterstützt du RoadLink und DNSmith: [PayPal](https://paypal.me/CoYoDuDe) oder [Buy Me a Coffee](https://www.buymeacoffee.com/CoYoDuDe). Die Nutzung ist nicht an eine Spende gebunden.
