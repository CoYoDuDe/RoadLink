import QtQuick 2
import com.victron.velib 1.0
MbPage {
    id: root
    title: qsTr("WLANs suchen")
    property bool requested: false
    property VBusItem scanRequest: VBusItem {
        bind: "com.coyodude.roadlink/Wifi/Scan/Request"
        onValidChanged: if (valid) root.startScan()
    }
    function startScan() {
        if (!requested && scanRequest.valid) { requested = true; scanRequest.setValue("scan") }
    }
    Component.onCompleted: startScan()
    model: VisibleItemModel {
        MbItemOptions {
            description: qsTr("Suche starten")
            text: qsTr("Suchen")
            bind: "com.coyodude.roadlink/Wifi/Scan/Request"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" }, MbOption { description: qsTr("Suchen"); value: "scan" }]
        }
        MbItemValue { description: qsTr("Suchstatus"); item.bind: "com.coyodude.roadlink/Wifi/Scan/Status" }
        MbSubMenu { description: qsTr("Gefundene WLANs"); item.bind: "com.coyodude.roadlink/Wifi/Scan/Count"; subpage: Component { PageRoadLinkScanResults {} } }
        MbItemText { text: qsTr("USB-WLAN-Reserve einschalten. Ein gefundenes WLAN wird erst nach dem Speichern verwendet. Ergebnisse gelten drei Minuten."); wrapMode: Text.WordWrap }
    }
}
