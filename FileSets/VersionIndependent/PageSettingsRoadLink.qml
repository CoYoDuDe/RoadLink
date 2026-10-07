import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("RoadLink")
    model: VisibleItemModel {
        MbSubMenu { description: qsTr("Fahrzeug-WLAN"); subpage: Component { PageRoadLinkAP {} } }
        MbSubMenu { description: qsTr("Externe WLANs"); subpage: Component { PageRoadLinkWifi {} } }
        MbSubMenu { description: qsTr("Internet und Umschaltung"); subpage: Component { PageRoadLinkWAN {} } }
        MbSubMenu { description: qsTr("Diagnose"); subpage: Component { PageRoadLinkDiagnostics {} } }
        MbItemValue { description: qsTr("Internet ueber"); item.bind: "com.coyodude.roadlink/Wan/Active" }
        MbItemValue { description: qsTr("Verbundenes WLAN"); item.bind: "com.coyodude.roadlink/WifiWan/SSID" }
        MbItemValue { description: qsTr("Internetstatus"); item.bind: "com.coyodude.roadlink/Wan/Health" }
        MbItemValue { description: qsTr("Fahrzeug-WLAN"); item.bind: "com.coyodude.roadlink/AP/Status" }
    }
}
