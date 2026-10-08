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
    property VBusItem rememberAvailable: VBusItem { bind: "com.coyodude.roadlink/Portal/Remember/Available" }
    property VBusItem rememberId: VBusItem { bind: "com.coyodude.roadlink/Portal/Remember/ID" }
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
        MbItemValue {
            description: qsTr("Erfolgreiches Portal")
            item.bind: "com.coyodude.roadlink/Portal/Remember/Summary"
            show: root.rememberAvailable.value === 1
        }
        MbItemText {
            text: qsTr("Nur bestaetigen, wenn diese Anmeldung kostenlos war und du die Bedingungen selbst akzeptiert hast. Bei unveraendertem Formular darf RoadLink dies kuenftig automatisch tun.")
            wrapMode: Text.WordWrap
            show: root.rememberAvailable.value === 1
        }
        MbItemOptions {
            description: qsTr("Kostenloses Portal merken")
            bind: "com.coyodude.roadlink/Portal/Remember/Request"
            writeAccessLevel: User.AccessInstaller
            show: root.rememberAvailable.value === 1
            enabled: root.rememberAvailable.value === 1 && root.rememberId.value !== ""
            readonly: !userHasWriteAccess || !enabled
            possibleValues: [MbOption { description: qsTr("Abbrechen"); value: "" },
                MbOption { description: qsTr("Kostenlos und Bedingungen akzeptiert"); value: "remember:" + root.rememberId.value }]
        }
        MbItemValue { description: qsTr("Portal merken"); item.bind: "com.coyodude.roadlink/Portal/Remember/Status" }
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
        MbItemValue {
            description: qsTr("Formularpruefung")
            item.bind: "com.coyodude.roadlink/Portal/FormStatus"
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
