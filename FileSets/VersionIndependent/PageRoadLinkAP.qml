import QtQuick 2
import com.victron.velib 1.0

MbPage {
    title: qsTr("RoadLink Fahrzeug-WLAN")
    model: VisibleItemModel {
        MbSwitch {
            name: qsTr("Fahrzeug-WLAN aktiv")
            bind: "com.victronenergy.settings/Settings/RoadLink/AP/Enabled"
            valueTrue: 1
            valueFalse: 0
            writeAccessLevel: User.AccessInstaller
        }
        MbEditBox {
            description: qsTr("WLAN-Name")
            item.bind: "com.victronenergy.settings/Settings/RoadLink/AP/SSID"
            maximumLength: 32
            overwriteMode: false
            writeAccessLevel: User.AccessInstaller
        }
        MbItemValue { description: qsTr("Status"); item.bind: "com.coyodude.roadlink/AP/Status" }
        MbItemValue { description: qsTr("Lokale IP-Adresse"); item.bind: "com.coyodude.roadlink/AP/Address" }
        MbItemText { text: qsTr("Internetfreigabe noch nicht aktiv") }
    }
}
