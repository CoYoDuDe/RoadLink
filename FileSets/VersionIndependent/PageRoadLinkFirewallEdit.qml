import QtQuick 2
import com.victron.velib 1.0
MbPage {
    id: root
    property string ruleId: ""
    property bool initialized: false
    property VBusItem ready: VBusItem { bind: "com.coyodude.roadlink/Firewall/Draft/Ready" }
    property VBusItem revision: VBusItem { bind: "com.coyodude.roadlink/Firewall/Revision" }
    property VBusItem editRequest: VBusItem {
        bind: "com.coyodude.roadlink/Firewall/Edit"
        onValidChanged: if (valid) root.initializeEditor()
    }
    function initializeEditor() {
        if (!initialized && editRequest.valid) {
            editRequest.setValue(ruleId || "new")
            initialized = true
        }
    }
    Component.onCompleted: initializeEditor()
    title: ruleId ? qsTr("Regel bearbeiten") : qsTr("Neue Firewall-Regel")
    model: VisibleItemModel {
        MbEditBox { show: root.ready.value === 1; description: qsTr("Name"); item.bind: "com.coyodude.roadlink/Firewall/Draft/Name"; maximumLength: 48; writeAccessLevel: User.AccessInstaller }
        MbSwitch { show: root.ready.value === 1; name: qsTr("Aktiv"); bind: "com.coyodude.roadlink/Firewall/Draft/Enabled"; valueTrue: 1; valueFalse: 0; writeAccessLevel: User.AccessInstaller }
        MbItemOptions {
            show: root.ready.value === 1; description: qsTr("Aktion"); bind: "com.coyodude.roadlink/Firewall/Draft/Action"; writeAccessLevel: User.AccessInstaller
            possibleValues: [MbOption { description: qsTr("Erlauben"); value: "allow" }, MbOption { description: qsTr("Sperren"); value: "block" }]
        }
        MbEditBox { show: root.ready.value === 1; description: qsTr("Geraete-IP (leer: alle)"); item.bind: "com.coyodude.roadlink/Firewall/Draft/Source"; maximumLength: 15; writeAccessLevel: User.AccessInstaller }
        MbEditBox { show: root.ready.value === 1; description: qsTr("Ziel-IP/Netz (leer: alle)"); item.bind: "com.coyodude.roadlink/Firewall/Draft/Destination"; maximumLength: 18; writeAccessLevel: User.AccessInstaller }
        MbItemOptions {
            show: root.ready.value === 1; description: qsTr("Protokoll"); bind: "com.coyodude.roadlink/Firewall/Draft/Protocol"; writeAccessLevel: User.AccessInstaller
            possibleValues: [MbOption { description: qsTr("Alle"); value: "any" }, MbOption { description: "TCP"; value: "tcp" }, MbOption { description: "UDP"; value: "udp" }]
        }
        MbEditBox { show: root.ready.value === 1; description: qsTr("Port (0: alle)"); item.bind: "com.coyodude.roadlink/Firewall/Draft/Port"; maximumLength: 5; numericOnlyLayout: true; writeAccessLevel: User.AccessInstaller }
        MbItemOptions {
            show: root.ready.value === 1; description: qsTr("Speichern"); bind: "com.coyodude.roadlink/Firewall/Save"; writeAccessLevel: User.AccessInstaller
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" }, MbOption { description: qsTr("Speichern"); value: "save" }]
        }
        MbItemOptions {
            show: root.ruleId !== "" && root.revision.value !== ""; description: qsTr("Regel verwalten"); bind: "com.coyodude.roadlink/Firewall/Action"; writeAccessLevel: User.AccessInstaller
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" },
                MbOption { description: qsTr("Nach oben"); value: "up:" + root.ruleId + ":" + root.revision.value },
                MbOption { description: qsTr("Nach unten"); value: "down:" + root.ruleId + ":" + root.revision.value },
                MbOption { description: qsTr("Loeschen"); value: "remove:" + root.ruleId + ":" + root.revision.value }]
        }
        MbItemValue { description: qsTr("Ergebnis"); item.bind: "com.coyodude.roadlink/Firewall/Status" }
        MbItemText { text: qsTr("Die erste passende eigene Regel gilt.") }
        MbItemText { text: qsTr("Nur oeffentliche IPv4-Ziele; DNS bleibt geschuetzt.") }
        MbItemText { text: qsTr("Geraete-IP muss zum Fahrzeugnetz gehoeren.") }
    }
}
