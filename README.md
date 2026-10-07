# RoadLink

Internet und eigenes Fahrzeug-WLAN für Venus OS auf dem Raspberry Pi.
**Entwicklungsstand v0.15 – noch keine fertige Endversion.**

## Installation

[SetupHelper von kwindrem](https://github.com/kwindrem/SetupHelper) installieren. Im Paketmanager eintragen:

- Paket: `RoadLink`
- GitHub-Benutzer: `CoYoDuDe`
- Branch: `main`

Danach **Einstellungen → RoadLink** öffnen. Benötigt werden die Venus-Pakete `hostapd`, `dnsmasq` und WireGuard. Fehlende Abhängigkeiten werden derzeit noch nicht automatisch installiert.

## Erste Einrichtung

1. USB-WLAN-Reserve einschalten und **WLANs suchen**. Ohne VPN arbeitet der Stick ausschließlich im Suchbetrieb.
2. Für das Fahrzeug-WLAN ein eigenes Passwort festlegen und es einschalten.
3. VPN mit einem eigenen Server einrichten; Anleitung unter [Technik und Einrichtung](docs/ARCHITECTURE.md).
4. Ein externes WLAN auswählen und speichern. Automatische Verbindung im gewünschten Profil freigeben.

Das Fahrzeug-WLAN heißt bei Neuinstallation **RoadLink**. Es gibt kein gemeinsames Standardpasswort und keine vorgegebenen externen WLANs oder Serverzugänge. WLAN und USB-Reserve starten ausgeschaltet; der Verbindungsmodus ist `AUTO`. Bestehende Einstellungen bleiben bei Updates erhalten.

## Was bereits funktioniert

- Eigenes Fahrzeug-WLAN mit WPA2 und getrennten WLAN-Clients.
- Externe WLANs suchen, hinzufügen, bearbeiten und entfernen; WPA2 oder offen.
- Gespeicherte, freigegebene WLANs automatisch verbinden; Priorität selbst festlegen.
- Optional unbekannte offene WLANs automatisch suchen und prüfen. Der Schalter startet ausgeschaltet. Erst nach bestätigtem VPN-, DNS- und Internetzugang über dieses WLAN wird es als bekanntes Netz gespeichert. Fehlgeschlagene Netze werden mit Wartezeit erneut geprüft.
- Profile als letzte Reserve markieren; normale bekannte oder gefundene offene Netze erhalten Vorrang. Innerhalb der Gruppe entscheidet die eingestellte Priorität.
- Optionalen Gerätenamen für externe WLANs einstellen; leer sendet keinen DHCP-Namen. Der Betreiber kann eine eigene Bezeichnung anzeigen. Der Fahrzeug-WLAN-Name ist unabhängig davon.
- Ethernet/Starlink oder USB-WLAN für den verschlüsselten VPN-Tunnel wählen.
- Aktives Netz, verbundenes WLAN und geprüften Internet-/DNS-Status im klassischen Venus-Menü sehen.
- Automatische Umschaltung bei Ausfall mit verzögerter Rückkehr, damit die Verbindung nicht ständig wechselt.

**Das Fahrzeug-WLAN erhält Internet nur über den geprüften VPN-Tunnel.** Eine WLAN-Verbindung oder IP-Adresse allein reicht nicht. Ethernet und SSH für den Gerätezugang bleiben erhalten. WLAN-Betreiber können weiterhin einen verbundenen Teilnehmer erkennen; RoadLink macht ihn nicht unsichtbar.

## Verbindungsmodi

### Fahrzeugnetz und VPN

Der Pi vergibt im Fahrzeug-WLAN eigene IP-Adressen per DHCP. Das externe WLAN wird nicht mit dem Fahrzeugnetz verbunden. Die Firewall sperrt neue Zugriffe von außen; der WLAN-Betreiber sieht keine einzelnen Fahrzeuggeräte als eigene WLAN- oder DHCP-Clients. Einen verbundenen Pi und dessen Verkehr kann er weiterhin erkennen.

Der VPN-Tunnel führt vom Pi zu einem externen WireGuard-Server. DNSmith wird auf diesem Gerät verwendet; andere Installationen benötigen ihre eigene Serverkonfiguration. Der Server ist die Gegenstelle für den verschlüsselten Internetverkehr. Ein rein lokaler VPN auf dem Pi ersetzt diese Gegenstelle nicht.

Geplant sind zwei getrennte Schalter: **DNSmith-VPN** und **DNSmith-DNS**, beide als Standard aktiviert. Bei Abwahl erscheinen die Felder für einen eigenen VPN-Anbieter beziehungsweise primären und sekundären DNS. Das ist von **Internet ohne VPN** zu unterscheiden. Neue Installationen benötigen eigene Schlüssel und eine eigene Clientregistrierung. Diese Anbieter-Einrichtung ist noch nicht verfügbar.

Ein ausdrücklicher Modus **Internet ohne VPN** ist ebenfalls geplant. Auch dort müssen eigenes DHCP, NAT, Firewall und die Sperre neuer eingehender Zugriffe erhalten bleiben. Ohne VPN entfällt dessen Verschlüsselung gegenüber dem externen WLAN. **Dieser Modus ist noch nicht verfügbar:** VPN-Abschalten sperrt derzeit das Fahrzeug-Internet. Es gibt keinen stillen unverschlüsselten Rückfall.

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

Updates und Deinstallation laufen über SetupHelper. Eigene Zugangsdaten und Schlüssel liegen ausschließlich lokal unter `/data/setupOptions/RoadLink`, außerhalb des Pakets. Nach einer Deinstallation bleiben sie für eine spätere Neuinstallation erhalten. Tests sind kein Bestandteil des veröffentlichten Pakets.

## Unterstützung

Die Pakete sind kostenlos. Freiwillige Unterstützung: [PayPal](https://paypal.me/CoYoDuDe), [Buy Me a Coffee](https://www.buymeacoffee.com/CoYoDuDe), [weitere Projekte](https://dnsmith.net/). Kein Abo-Zwang.
