import QtQuick 2
import com.victron.velib 1.0
MbPage {
    id: root
    title: qsTr("WLAN-Anmeldung")
    property string deviceId: ""
    property string deviceName: ""
    property VBusItem available: VBusItem { bind: "com.coyodude.roadlink/Portal/Available" }
    property VBusItem selected: VBusItem { bind: "com.coyodude.roadlink/Portal/SelectedDevice" }
    property VBusItem state: VBusItem { bind: "com.coyodude.roadlink/Portal/State" }
    model: VisibleItemModel {
        MbItemOptions {
            description: qsTr("Bekannte Portale automatisch")
            bind: "com.coyodude.roadlink/Portal/Known/AutoAccept"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [MbOption { description: qsTr("Aus"); value: 0 },
                             MbOption { description: qsTr("Ein"); value: 1 }]
        }
        MbSubMenu { description: qsTr("Bekannte Portale"); subpage: Component { PageRoadLinkKnownPortals {} } }
        MbItemValue { description: qsTr("Portalprofile"); item.bind: "com.coyodude.roadlink/Portal/Known/Status" }
        MbItemValue { description: qsTr("Status"); item.bind: "com.coyodude.roadlink/Portal/Status" }
        MbSubMenu {
            description: qsTr("Fahrzeuggeraet auswaehlen")
            show: root.deviceId === ""
            subpage: Component { PageRoadLinkPortalDevices {} }
        }
        MbItemOptions {
            description: qsTr("Dieses Geraet verwenden")
            text: root.deviceName
            show: root.deviceId !== ""
            bind: "com.coyodude.roadlink/Portal/SelectedDevice"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" },
                MbOption { description: root.deviceName; value: root.deviceId }]
        }
        MbEditBox {
            description: qsTr("Zusaetzliche Portal-Domains")
            item.bind: "com.coyodude.roadlink/Portal/AdditionalDomains"
            maximumLength: 1000
            overwriteMode: false
            writeAccessLevel: User.AccessInstaller
            enabled: root.available.value === 1 && root.state.value === "OFF"
            readonly: !userHasWriteAccess || !enabled
        }
        MbItemText {
            text: qsTr("Optional: bis zu drei benoetigte Domains mit Komma trennen. Nur fuer diese Anmeldung freigeben.")
            wrapMode: Text.WordWrap
            show: root.available.value === 1 && root.state.value === "OFF"
        }
        MbItemOptions {
            description: qsTr("Anmeldung starten")
            bind: "com.coyodude.roadlink/Portal/Request"
            writeAccessLevel: User.AccessInstaller
            enabled: root.available.value === 1 && root.selected.value !== "" &&
                (root.deviceId === "" || root.selected.value === root.deviceId) && root.state.value === "OFF"
            readonly: !userHasWriteAccess || !enabled
            greyed: readonly
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" },
                MbOption { description: qsTr("Freigabe starten"); value: "start" }]
        }
        MbItemValue {
            description: qsTr("Anmeldeseite")
            item.bind: "com.coyodude.roadlink/Portal/URL"
            show: root.state.value === "LOGIN_READY"
        }
        MbItemText {
            text: qsTr("Diese Adresse im Browser des ausgewaehlten Fahrzeuggeraets oeffnen.")
            wrapMode: Text.WordWrap
            show: root.state.value === "LOGIN_READY"
        }
        MbItemText {
            text: qsTr("Falls die Seite nicht erreichbar ist: am gewaehlten Geraet das Fahrzeug-WLAN kurz trennen und neu verbinden.")
            wrapMode: Text.WordWrap
            show: root.state.value === "LOGIN_READY"
        }
        MbItemOptions {
            description: qsTr("Anmeldung beenden")
            bind: "com.coyodude.roadlink/Portal/Request"
            writeAccessLevel: User.AccessInstaller
            enabled: root.state.value !== "OFF"
            readonly: !userHasWriteAccess || !enabled
            greyed: readonly
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" },
                MbOption { description: qsTr("Freigabe beenden"); value: "stop" }]
        }
        MbItemValue { description: qsTr("Ergebnis"); item.bind: "com.coyodude.roadlink/Portal/EditStatus" }
        MbItemText { text: qsTr("Nur Portal-Zugriff, hoechstens 15 Minuten. Internet wird danach getrennt geprueft."); wrapMode: Text.WordWrap }
    }
}
