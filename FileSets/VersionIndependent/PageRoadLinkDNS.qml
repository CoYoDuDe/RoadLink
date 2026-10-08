import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("RoadLink DNS")
    property VBusItem useDNSmith: VBusItem { bind: "com.coyodude.roadlink/DNS/UseDNSmith" }
    property VBusItem vpnRequired: VBusItem { bind: "com.coyodude.roadlink/Transport/VPNRequired" }
    model: VisibleItemModel {
        MbSwitch { name: qsTr("DNSmith-DNS"); bind: "com.coyodude.roadlink/DNS/UseDNSmith"; valueTrue: 1; valueFalse: 0; writeAccessLevel: User.AccessInstaller }
        MbItemValue { description: qsTr("Aktiver Anbieter"); item.bind: "com.coyodude.roadlink/DNS/Provider" }
        MbItemValue { description: qsTr("Gepruefter DNS"); item.bind: "com.coyodude.roadlink/DNS/Active" }
        MbEditBox { description: qsTr("Primaer IPv4"); item.bind: "com.coyodude.roadlink/DNS/Primary"; maximumLength: 15; show: useDNSmith.value === 0; writeAccessLevel: User.AccessInstaller }
        MbEditBox { description: qsTr("Sekundaer IPv4 (optional)"); item.bind: "com.coyodude.roadlink/DNS/Secondary"; maximumLength: 15; show: useDNSmith.value === 0; writeAccessLevel: User.AccessInstaller }
        MbItemOptions {
            description: qsTr("DNS-Einstellungen speichern")
            bind: "com.coyodude.roadlink/DNS/Save"
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" }, MbOption { description: qsTr("Speichern"); value: "save" }]
            show: useDNSmith.value === 0
            writeAccessLevel: User.AccessInstaller
        }
        MbItemValue { description: qsTr("Ergebnis"); item.bind: "com.coyodude.roadlink/DNS/EditStatus" }
        MbItemText { text: qsTr("Cloudflare: 1.1.1.1 / 1.0.0.1"); show: useDNSmith.value === 0 }
        MbItemText { text: qsTr("Google: 8.8.8.8 / 8.8.4.4"); show: useDNSmith.value === 0 }
        MbItemText { text: qsTr("Neue Adressen erst speichern."); show: useDNSmith.value === 0 }
        MbItemText { text: qsTr("DNS bleibt im VPN-Tunnel."); show: vpnRequired.value === 1 }
        MbItemText { text: qsTr("Ohne VPN: DNS unverschluesselt."); show: vpnRequired.value === 0 }
    }
}
