import QtQuick 2
import com.victron.velib 1.0
MbPage {
    title: qsTr("Eigene Firewall-Regeln")
    property VBusItem rules: VBusItem { bind: "com.coyodude.roadlink/Firewall/Rules" }
    property var entries: rules.valid ? JSON.parse(rules.value) : []
    model: entries.length ? entries : [{id: "", name: qsTr("Noch keine eigenen Regeln"), enabled: false}]
    delegate: MbSubMenu {
        description: (index + 1) + ". " + modelData.name + (modelData.id && !modelData.enabled ? qsTr(" (aus)") : "")
        subpage: Component { PageRoadLinkFirewallEdit { ruleId: modelData.id || "" } }
        enabled: modelData.id !== ""
    }
}
