import QtQuick 2
import com.victron.velib 1.0
MbPage {
    id: root
    property string profileId: ""
    property string scanId: ""
    property bool initialized: false
    property VBusItem editRequest: VBusItem {
        bind: "com.coyodude.roadlink/Wifi/Edit"
        onValidChanged: if (valid) root.initializeEditor()
    }
    function initializeEditor() {
        if (!initialized && editRequest.valid) {
            editRequest.setValue(profileId || (scanId ? "scan:" + scanId : "new"))
            initialized = true
        }
    }
    Component.onCompleted: initializeEditor()
    title: profileId ? qsTr("WLAN bearbeiten") : qsTr("Externes WLAN speichern")
    model: VisibleItemModel {
        MbEditBox { description: qsTr("WLAN-Name"); item.bind: "com.coyodude.roadlink/Wifi/Draft/SSID"; maximumLength: 32; writeAccessLevel: User.AccessInstaller }
        MbItemOptions {
            description: qsTr("Sicherheit")
            bind: "com.coyodude.roadlink/Wifi/Draft/Security"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [MbOption { description: qsTr("WPA2"); value: "psk" }, MbOption { description: qsTr("Offenes WLAN"); value: "open" }]
        }
        RoadLinkPasswordEditor { description: qsTr("Passwort eingeben"); item.bind: "com.coyodude.roadlink/Wifi/Draft/Password" }
        MbEditBox { description: qsTr("Prioritaet 0-100"); item.bind: "com.coyodude.roadlink/Wifi/Draft/Priority"; maximumLength: 3; numericOnlyLayout: true; writeAccessLevel: User.AccessInstaller }
        MbSwitch { name: qsTr("Automatisch verbinden"); bind: "com.coyodude.roadlink/Wifi/Draft/AutoConnect"; valueTrue: 1; valueFalse: 0; writeAccessLevel: User.AccessInstaller }
        MbSwitch { name: qsTr("Nur als letzte Reserve"); bind: "com.coyodude.roadlink/Wifi/Draft/LastResort"; writeAccessLevel: User.AccessInstaller }
        MbItemOptions {
            description: qsTr("Profil speichern")
            bind: "com.coyodude.roadlink/Wifi/Draft/Save"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" }, MbOption { description: qsTr("Speichern"); value: "save" }]
        }
        MbItemValue { description: qsTr("Ergebnis"); item.bind: "com.coyodude.roadlink/Wifi/EditStatus" }
        MbItemText { text: qsTr("Internet wird nur ueber den VPN-Tunnel freigegeben.") }
    }
}
