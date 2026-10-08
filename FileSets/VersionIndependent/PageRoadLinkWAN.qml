import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("RoadLink Internet")
    property VBusItem vpnRequired: VBusItem { bind: "com.coyodude.roadlink/Transport/VPNRequired" }
    model: VisibleItemModel {
        MbSwitch { name: qsTr("Internet ueber VPN"); bind: "com.coyodude.roadlink/Transport/VPNRequired"; valueTrue: 1; valueFalse: 0; writeAccessLevel: User.AccessInstaller }
        MbItemValue { description: qsTr("Betriebsart"); item.bind: "com.coyodude.roadlink/Transport/Status" }
        MbItemText { text: qsTr("Ohne VPN keine Tunnelverschluesselung."); show: vpnRequired.value === 0 }
        MbSubMenu { description: qsTr("VPN-Anbieter"); show: vpnRequired.value === 1; subpage: Component { PageRoadLinkVPN {} } }
        MbSubMenu { description: qsTr("DNS-Anbieter"); subpage: Component { PageRoadLinkDNS {} } }
        MbItemOptions {
            description: qsTr("Verbindungsmodus")
            bind: "com.victronenergy.settings/Settings/RoadLink/Wan/Mode"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [
                MbOption { description: qsTr("Automatisch"); value: "AUTO" },
                MbOption { description: qsTr("Starlink bevorzugen"); value: "PREFER_STARLINK" },
                MbOption { description: qsTr("WLAN bevorzugen"); value: "PREFER_WIFI" },
                MbOption { description: qsTr("Bessere Verbindung"); value: "BEST_CONNECTION" },
                MbOption { description: qsTr("Nur Starlink"); value: "STARLINK_ONLY" },
                MbOption { description: qsTr("Nur WLAN"); value: "WIFI_ONLY" }
            ]
        }
        MbItemValue { description: qsTr("Internet ueber"); item.bind: "com.coyodude.roadlink/Wan/Active" }
        MbItemValue { description: qsTr("Internetstatus"); item.bind: "com.coyodude.roadlink/Wan/Health" }
        MbItemValue { description: qsTr("Umschaltung"); item.bind: "com.coyodude.roadlink/Wan/Reason" }
        MbItemValue { description: qsTr("Beschleunigung"); item.bind: "com.coyodude.roadlink/Wan/Acceleration" }
        MbItemValue { description: qsTr("VPN-Verbindung"); item.bind: "com.coyodude.roadlink/VPN/Status"; show: vpnRequired.value === 1 }
        MbItemValue { description: qsTr("Gepruefter DNS"); item.bind: "com.coyodude.roadlink/DNS/Active" }
        MbSwitch {
            name: qsTr("DNSmith automatisch einrichten")
            bind: "com.victronenergy.settings/Settings/RoadLink/VPN/AutoEnroll"
            valueTrue: 1
            valueFalse: 0
            writeAccessLevel: User.AccessInstaller
            show: vpnRequired.value === 1
        }
        MbItemValue { description: qsTr("Einrichtung"); item.bind: "com.coyodude.roadlink/VPN/Enrollment"; show: vpnRequired.value === 1 }
        MbItemText { text: qsTr("Standardanbieter: DNSmith.net") }
        MbItemText { text: qsTr("Kostenlos; Unterstuetzung freiwillig") }
    }
}
