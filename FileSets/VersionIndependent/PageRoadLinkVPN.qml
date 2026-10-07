import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("RoadLink VPN")
    property VBusItem useDNSmith: VBusItem { bind: "com.coyodude.roadlink/VPN/UseDNSmith" }
    property VBusItem deviceKey: VBusItem { bind: "com.coyodude.roadlink/VPN/ClientPublicKey" }
    model: VisibleItemModel {
        MbSwitch { name: qsTr("DNSmith-VPN"); bind: "com.coyodude.roadlink/VPN/UseDNSmith"; valueTrue: 1; valueFalse: 0; writeAccessLevel: User.AccessInstaller }
        MbItemValue { description: qsTr("Anbieterstatus"); item.bind: "com.coyodude.roadlink/VPN/ProviderStatus" }
        MbSwitch { name: qsTr("Automatisch einrichten"); bind: "com.victronenergy.settings/Settings/RoadLink/VPN/AutoEnroll"; valueTrue: 1; valueFalse: 0; show: useDNSmith.value === 1; writeAccessLevel: User.AccessInstaller }
        MbItemValue { description: qsTr("Einrichtung"); item.bind: "com.coyodude.roadlink/VPN/Enrollment"; show: useDNSmith.value === 1 }
        MbEditBox { description: qsTr("Server IPv4"); item.bind: "com.coyodude.roadlink/VPN/Custom/Endpoint"; maximumLength: 15; show: useDNSmith.value === 0; writeAccessLevel: User.AccessInstaller }
        MbEditBox { description: qsTr("Server-Port"); item.bind: "com.coyodude.roadlink/VPN/Custom/Port"; maximumLength: 5; numericOnlyLayout: true; show: useDNSmith.value === 0; writeAccessLevel: User.AccessInstaller }
        MbEditBox { description: qsTr("Server-Public-Key"); item.bind: "com.coyodude.roadlink/VPN/Custom/ServerKey"; maximumLength: 44; show: useDNSmith.value === 0; writeAccessLevel: User.AccessInstaller }
        MbEditBox { description: qsTr("Client IPv4/32"); item.bind: "com.coyodude.roadlink/VPN/Custom/Address"; maximumLength: 18; show: useDNSmith.value === 0; writeAccessLevel: User.AccessInstaller }
        MbEditBox { description: qsTr("Profil-DNS IPv4"); item.bind: "com.coyodude.roadlink/VPN/Custom/DNS"; maximumLength: 15; show: useDNSmith.value === 0; writeAccessLevel: User.AccessInstaller }
        MbEditBox { description: qsTr("MTU 1280-1420"); item.bind: "com.coyodude.roadlink/VPN/Custom/MTU"; maximumLength: 4; numericOnlyLayout: true; show: useDNSmith.value === 0; writeAccessLevel: User.AccessInstaller }
        MbItemOptions {
            description: qsTr("Eigene Einstellungen speichern")
            bind: "com.coyodude.roadlink/VPN/Custom/Save"
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" }, MbOption { description: qsTr("Speichern"); value: "save" }]
            show: useDNSmith.value === 0
            writeAccessLevel: User.AccessInstaller
        }
        MbItemOptions {
            description: qsTr("Geraete-Public-Key anzeigen")
            bind: "com.coyodude.roadlink/VPN/ShowPublicKey"
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" }, MbOption { description: qsTr("Anzeigen"); value: "show" }]
            show: useDNSmith.value === 0
            writeAccessLevel: User.AccessInstaller
        }
        MbItemText { text: String(deviceKey.value || "").substring(0, 22); show: useDNSmith.value === 0 && deviceKey.value !== "" }
        MbItemText { text: String(deviceKey.value || "").substring(22); show: useDNSmith.value === 0 && deviceKey.value !== "" }
        MbItemText { text: qsTr("Public Key am Server eintragen."); show: useDNSmith.value === 0 }
        MbItemText { text: qsTr("Aktiven DNS unter DNS-Anbieter waehlen."); show: useDNSmith.value === 0 }
        MbItemText { text: qsTr("Ohne VPN kein Fahrzeug-Internet."); show: useDNSmith.value === 0 }
        MbItemText { text: qsTr("Beide Anbieter bleiben gespeichert.") }
        MbItemText { text: qsTr("DNSmith.net: kostenlos"); show: useDNSmith.value === 1 }
        MbItemText { text: qsTr("Spenden sind freiwillig."); show: useDNSmith.value === 1 }
    }
}
