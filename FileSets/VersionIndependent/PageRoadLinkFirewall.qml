import QtQuick 2
import com.victron.velib 1.0
MbPage {
    id: root
    title: qsTr("Firewall")
    property VBusItem revision: VBusItem { bind: "com.coyodude.roadlink/Firewall/Revision" }
    property VBusItem defaultRule: VBusItem { bind: "com.coyodude.roadlink/Firewall/Default" }
    model: VisibleItemModel {
        MbItemValue { description: qsTr("Betrieb"); item.bind: "com.coyodude.roadlink/Firewall/ApplyStatus" }
        MbSubMenu { description: qsTr("Eigene Regeln"); subpage: Component { PageRoadLinkFirewallRules {} } }
        MbSubMenu { description: qsTr("Neue Regel"); subpage: Component { PageRoadLinkFirewallEdit {} } }
        MbItemText { text: defaultRule.value === "block" ? qsTr("Ohne passende Regel: sperren") : qsTr("Ohne passende Regel: erlauben") }
        MbItemOptions {
            description: qsTr("Standard aendern")
            bind: "com.coyodude.roadlink/Firewall/Action"
            writeAccessLevel: User.AccessInstaller
            readonly: !userHasWriteAccess || !root.revision.value
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" },
                MbOption { description: qsTr("Erlauben"); value: "default:allow:" + root.revision.value },
                MbOption { description: qsTr("Sperren"); value: "default:block:" + root.revision.value }]
        }
        MbItemValue { description: qsTr("Ergebnis"); item.bind: "com.coyodude.roadlink/Firewall/Status" }
        MbItemText { text: qsTr("Regeln gelten fuer ausgehendes Internet.") }
        MbItemText { text: qsTr("Trennung, DNS und VPN-Schutz bleiben fest.") }
        MbItemText { text: qsTr("Aenderungen starten das Netzwerk kontrolliert neu.") }
    }
}
