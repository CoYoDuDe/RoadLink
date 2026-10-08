import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("RoadLink Externe WLANs")
    model: VisibleItemModel {
        MbSubMenu { description: qsTr("Bekannte WLANs"); subpage: Component { PageRoadLinkWifiProfiles {} } }
        MbSubMenu { description: qsTr("WLANs suchen"); subpage: Component { PageRoadLinkScan {} } }
        MbSubMenu { description: qsTr("WLAN hinzufuegen"); subpage: Component { PageRoadLinkWifiAdd {} } }
        MbSwitch { name: qsTr("WLAN-Reserve aktiv"); bind: "com.victronenergy.settings/Settings/RoadLink/WifiWan/Enabled"; writeAccessLevel: User.AccessInstaller }
        MbSwitch { name: qsTr("Offene WLANs automatisch pruefen"); bind: "com.victronenergy.settings/Settings/RoadLink/WifiWan/AutoOpen"; writeAccessLevel: User.AccessInstaller }
        MbItemValue { description: qsTr("Verbindung"); item.bind: "com.coyodude.roadlink/WifiWan/StateText" }
        MbItemValue { description: qsTr("Funkmodul"); item.bind: "com.coyodude.roadlink/Radio/WanRadio" }
        MbItemValue { description: qsTr("WLAN-Name"); item.bind: "com.coyodude.roadlink/WifiWan/SSID" }
        MbEditBox {
            description: qsTr("Geraetename (optional)")
            item.bind: "com.coyodude.roadlink/WifiWan/ClientName"
            maximumLength: 63
            overwriteMode: false
            writeAccessLevel: User.AccessInstaller
            function editTextToValue() {
                return _editText === "" || /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(_editText) ? _editText : null
            }
        }
        MbItemValue { description: qsTr("Namestatus"); item.bind: "com.coyodude.roadlink/WifiWan/ClientNameStatus" }
        MbItemText { text: qsTr("Leer: kein DHCP-Name") }
        MbItemText { text: qsTr("Gepruefte offene WLANs") }
        MbItemText { text: qsTr("werden automatisch gespeichert.") }
    }
}
