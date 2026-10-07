import QtQuick 2
import com.victron.velib 1.0
MbPage {
    id: root
    property variant profile: ({})
    title: profile.ssid || qsTr("WLAN-Profil")
    model: VisibleItemModel {
        MbItemText { text: qsTr("VPN erforderlich") }
        MbItemText { text: qsTr("Prioritaet: ") + root.profile.priority }
        MbItemText { text: root.profile.autoconnect ? qsTr("Automatische Verbindung vorgesehen") : qsTr("Automatische Verbindung aus") }
        MbItemText { text: qsTr("Zum Aendern mit gleichem Namen speichern") }
        MbItemOptions {
            description: qsTr("WLAN vergessen")
            bind: "com.coyodude.roadlink/Wifi/Forget"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" }, MbOption { description: qsTr("Entfernen"); value: root.profile.id || "" }]
        }
        MbItemValue { description: qsTr("Ergebnis"); item.bind: "com.coyodude.roadlink/Wifi/EditStatus" }
    }
}
