import QtQuick 2
import com.victron.velib 1.0
import "utils.js" as Utils

MbPage {
    title: qsTr("RoadLink")
    model: VisibleItemModel {
        MbItemValue { description: qsTr("Betriebszustand"); item.bind: "com.coyodude.roadlink/Status" }
        MbItemValue { description: qsTr("Starlink / Ethernet"); item.bind: "com.coyodude.roadlink/Ethernet" }
        MbItemValue { description: qsTr("USB-WLAN"); item.bind: "com.coyodude.roadlink/WifiWan" }
        MbItemValue { description: qsTr("Fahrzeug-AP: Funkmodul"); item.bind: "com.coyodude.roadlink/VehicleAp" }
        MbItemValue { description: qsTr("Standardroute"); item.bind: "com.coyodude.roadlink/DefaultInterface" }
        MbItemValue { description: qsTr("VPN-/DNS-Schutz"); item.bind: "com.coyodude.roadlink/Security" }
    }
}
