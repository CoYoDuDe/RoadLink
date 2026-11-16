import QtQuick 2
import com.victron.velib 1.0

MbPage {
    title: qsTr("RoadLink Fahrzeug-WLAN")
    property VBusItem apBand: VBusItem { bind: "com.coyodude.roadlink/AP/Band" }
    model: VisibleItemModel {
        MbSwitch {
            name: qsTr("Fahrzeug-WLAN aktiv")
            bind: "com.victronenergy.settings/Settings/RoadLink/AP/Enabled"
            valueTrue: 1
            valueFalse: 0
            writeAccessLevel: User.AccessInstaller
        }
        MbEditBox {
            description: qsTr("WLAN-Name")
            item.bind: "com.victronenergy.settings/Settings/RoadLink/AP/SSID"
            maximumLength: 32
            overwriteMode: false
            writeAccessLevel: User.AccessInstaller
        }
        MbItemOptions {
            description: qsTr("Fahrzeug-WLAN ueber")
            bind: "com.coyodude.roadlink/Radio/VehicleAP"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [
                MbOption { description: qsTr("Integriertes WLAN"); value: "internal" },
                MbOption { description: qsTr("USB-Stick"); value: "usb" }
            ]
        }
        MbItemValue { description: qsTr("Funkbetrieb"); item.bind: "com.coyodude.roadlink/AP/Radio" }
        MbItemOptions {
            description: qsTr("Frequenzband")
            bind: "com.coyodude.roadlink/AP/Band"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [
                MbOption { description: qsTr("2,4 GHz (Reichweite)"); value: "2.4" },
                MbOption { description: qsTr("5 GHz (schneller)"); value: "5" }
            ]
        }
        MbItemOptions {
            description: qsTr("Kanal")
            bind: "com.coyodude.roadlink/AP/Channel"
            show: apBand.value === "2.4"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [
                MbOption { description: "1"; value: 1 },
                MbOption { description: "6"; value: 6 },
                MbOption { description: "11"; value: 11 }
            ]
        }
        MbItemOptions {
            description: qsTr("Kanal")
            bind: "com.coyodude.roadlink/AP/Channel"
            show: apBand.value === "5"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [
                MbOption { description: "36"; value: 36 },
                MbOption { description: "40"; value: 40 },
                MbOption { description: "44"; value: 44 },
                MbOption { description: "48"; value: 48 }
            ]
        }
        MbItemOptions {
            description: qsTr("Kanalbreite")
            bind: "com.coyodude.roadlink/AP/Width"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [
                MbOption { description: qsTr("Automatisch"); value: 0 },
                MbOption { description: "20 MHz"; value: 20 },
                MbOption { description: "40 MHz"; value: 40 },
                MbOption { description: qsTr("80 MHz (nur 5 GHz)"); value: 80 }
            ]
        }
        MbItemOptions {
            description: qsTr("Verschluesselung")
            bind: "com.coyodude.roadlink/AP/Security"
            writeAccessLevel: User.AccessInstaller
            possibleValues: [
                MbOption { description: qsTr("WPA2 (AES)"); value: "wpa2" },
                MbOption { description: qsTr("WPA2/WPA3 gemischt"); value: "wpa2_wpa3" },
                MbOption { description: qsTr("Nur WPA3"); value: "wpa3" }
            ]
        }
        MbItemValue { description: qsTr("Funkeinstellung"); item.bind: "com.coyodude.roadlink/AP/RadioEditStatus" }
        MbItemValue { description: qsTr("Externe WLANs ueber"); item.bind: "com.coyodude.roadlink/Radio/WanRadio" }
        MbItemValue { description: qsTr("Funkzuordnung"); item.bind: "com.coyodude.roadlink/Radio/EditStatus" }
        MbItemValue { description: qsTr("Status"); item.bind: "com.coyodude.roadlink/AP/Status" }
        MbEditBox {
            id: passwordEditor
            description: qsTr("Passwort setzen")
            item.bind: "com.coyodude.roadlink/AP/NewPassword"
            maximumLength: 63
            enableSpaceBar: true
            overwriteMode: false
            writeAccessLevel: User.AccessInstaller
            textInput.text: editMode ? new Array(_editText.length + 1).join("*") : qsTr("Neu eingeben")
            function getEditText() { return "" }
            function editTextToValue() {
                return /^[\x20-\x7e]{8,63}$/.test(_editText) ? _editText : null
            }
            onEditModeChanged: if (!editMode) _editText = ""
        }
        MbItemValue { description: qsTr("Passwortstatus"); item.bind: "com.coyodude.roadlink/AP/PasswordStatus" }
        MbItemValue { description: qsTr("Lokale IP-Adresse"); item.bind: "com.coyodude.roadlink/AP/Address" }
        MbSubMenu {
            description: qsTr("Verbundene Geraete")
            subpage: Component { PageRoadLinkClients {} }
        }
        MbItemText { text: qsTr("Eigenes DHCP und Fahrzeugnetz") }
        MbItemText { text: qsTr("Zugriffe aus fremden WLANs gesperrt") }
    }
}
