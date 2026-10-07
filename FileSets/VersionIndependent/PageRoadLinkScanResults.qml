import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("Gefundene WLANs")
    property VBusItem results: VBusItem { bind: "com.coyodude.roadlink/Wifi/Scan/Results" }
    model: results.valid ? JSON.parse(results.value) : []
    delegate: MbSubMenu {
        description: modelData.ssid
        item.text: modelData.signal + " dBm / " + (modelData.security === "psk" ? "WPA2" : modelData.security === "open" ? qsTr("offen") : qsTr("nicht unterstuetzt"))
        enabled: modelData.security !== "unsupported"
        subpage: Component { PageRoadLinkWifiAdd { scanId: modelData.id } }
    }
}
