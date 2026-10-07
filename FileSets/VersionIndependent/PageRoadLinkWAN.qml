import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("RoadLink Internet")
    model: VisibleItemModel {
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
        MbItemValue { description: qsTr("VPN-Verbindung"); item.bind: "com.coyodude.roadlink/VPN/Status" }
        MbItemValue { description: qsTr("DNS"); item.bind: "com.coyodude.roadlink/VPN/DNS" }
    }
}
