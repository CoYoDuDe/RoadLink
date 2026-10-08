import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("Fahrzeuggeraete")
    property VBusItem devices: VBusItem { bind: "com.coyodude.roadlink/Portal/Devices" }
    property var availableDevices: devices.valid ? JSON.parse(devices.value) : []
    model: availableDevices.length ? availableDevices :
        [{id: "", name: qsTr("Keine Geraete fuer Anmeldung verfuegbar"), ip: ""}]
    delegate: MbItemOptions {
        description: modelData.name || modelData.ip
        enabled: modelData.id !== ""
        readonly: !userHasWriteAccess || modelData.id === ""
        greyed: readonly
        text: modelData.ip
        bind: "com.coyodude.roadlink/Portal/SelectedDevice"
        writeAccessLevel: User.AccessInstaller
        possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" },
            MbOption { description: qsTr("Dieses Geraet verwenden"); value: modelData.id }]
    }
}
