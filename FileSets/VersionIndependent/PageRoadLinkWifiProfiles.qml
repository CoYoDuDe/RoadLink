import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("Gespeicherte WLANs")
    property VBusItem profiles: VBusItem { bind: "com.coyodude.roadlink/Wifi/Profiles" }
    model: [{ssid: qsTr("Neues WLAN hinzufuegen"), newProfile: true}].concat(profiles.valid ? JSON.parse(profiles.value) : [])
    delegate: MbSubMenu {
        description: modelData.ssid
        item.text: modelData.newProfile ? "" : qsTr("Prioritaet ") + modelData.priority
        subpage: modelData.newProfile ? addPage : detailPage
        Component { id: addPage; PageRoadLinkWifiAdd {} }
        Component { id: detailPage; PageRoadLinkWifiProfile { profile: modelData } }
    }
}
