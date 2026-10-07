import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("Gespeicherte WLANs")
    property VBusItem profiles: VBusItem { bind: "com.coyodude.roadlink/Wifi/Profiles" }
    model: profiles.valid ? JSON.parse(profiles.value) : []
    delegate: MbSubMenu {
        description: modelData.ssid
        item.text: qsTr("Prioritaet ") + modelData.priority
        subpage: Component { PageRoadLinkWifiProfile { profile: modelData } }
    }
    MbItemText { visible: model.length === 0; text: qsTr("Noch keine WLANs gespeichert") }
}
