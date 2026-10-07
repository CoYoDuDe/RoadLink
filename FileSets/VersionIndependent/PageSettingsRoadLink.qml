import QtQuick 2
import com.victron.velib 1.0
import "utils.js" as Utils

MbPage {
    title: qsTr("RoadLink")
    model: VisibleItemModel {
        MbSubMenu { description: qsTr("Fahrzeug-WLAN"); subpage: Component { PageRoadLinkAP {} } }
        MbSubMenu { description: qsTr("Externes WLAN hinzufuegen"); subpage: Component { PageRoadLinkWifiAdd {} } }
        MbSubMenu { description: qsTr("Gespeicherte WLANs"); subpage: Component { PageRoadLinkWifiProfiles {} } }
        MbItemValue { description: qsTr("Aktueller WAN-Pfad"); item.bind: "com.coyodude.roadlink/Wan/Active" }
        MbItemValue { description: qsTr("Verbundenes WLAN"); item.bind: "com.coyodude.roadlink/WifiWan/SSID" }
        MbItemValue { description: qsTr("Internetstatus"); item.bind: "com.coyodude.roadlink/Wan/Health" }
        MbItemValue { description: qsTr("WAN-Umschaltung"); item.bind: "com.coyodude.roadlink/Wan/Reason" }
        MbItemValue { description: qsTr("Beschleunigung"); item.bind: "com.coyodude.roadlink/Wan/Acceleration" }
        MbItemValue { description: qsTr("Betriebszustand"); item.bind: "com.coyodude.roadlink/Status" }
        MbItemValue { description: qsTr("Starlink / Ethernet"); item.bind: "com.coyodude.roadlink/Ethernet" }
        MbItemValue { description: qsTr("USB-WLAN"); item.bind: "com.coyodude.roadlink/WifiWan" }
        MbItemValue { description: qsTr("Fahrzeug-AP: Funkmodul"); item.bind: "com.coyodude.roadlink/VehicleAp" }
        MbItemValue { description: qsTr("Standardroute"); item.bind: "com.coyodude.roadlink/DefaultInterface" }
        MbItemValue { description: qsTr("VPN-/DNS-Schutz"); item.bind: "com.coyodude.roadlink/Security" }
    }
}
