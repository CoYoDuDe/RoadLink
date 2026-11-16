import QtQuick 2
import com.victron.velib 1.0

MbPage {
    id: root
    property int index: 0
    property string base: "com.coyodude.roadlink/Clients/" + index + "/"
    property VBusItem nameItem: VBusItem { bind: root.base + "Name" }
    title: nameItem.value !== undefined && nameItem.value !== null && String(nameItem.value) !== "" ? String(nameItem.value) : qsTr("Geraet")
    model: VisibleItemModel {
        MbItemValue { description: qsTr("Name"); item.bind: root.base + "Name" }
        MbItemValue { description: qsTr("IP-Adresse"); item.bind: root.base + "Ip" }
        MbItemValue { description: qsTr("MAC-Adresse"); item.bind: root.base + "Mac" }
        MbItemValue { description: qsTr("Signal"); item.bind: root.base + "Signal" }
        MbItemValue { description: qsTr("Verbunden seit"); item.bind: root.base + "Connected" }
        MbSwitch {
            name: qsTr("Geraet sperren")
            bind: root.base + "Blocked"
            valueTrue: 1
            valueFalse: 0
            writeAccessLevel: User.AccessInstaller
        }
        MbItemText { text: qsTr("Sperren trennt das Geraet sofort, ohne WLAN-Neustart") }
    }
}
