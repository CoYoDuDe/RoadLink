import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("Bekannte Portale")
    property VBusItem profiles: VBusItem { bind: "com.coyodude.roadlink/Portal/Known/Profiles" }
    property var entries: profiles.valid ? JSON.parse(profiles.value) : []
    model: entries.length ? entries : [{id: "", ssid: qsTr("Noch keine bestaetigten Portale"), host: ""}]
    delegate: MbItemOptions {
        description: modelData.ssid
        text: modelData.host
        bind: modelData.id ? "com.coyodude.roadlink/Portal/Known/Profiles/" + modelData.id + "/AutoAccept" : ""
        writeAccessLevel: User.AccessInstaller
        readonly: !userHasWriteAccess || modelData.id === ""
        greyed: readonly
        possibleValues: [MbOption { description: qsTr("Automatisch: Aus"); value: 0 },
                         MbOption { description: qsTr("Automatisch: Ein"); value: 1 }]
    }
}
