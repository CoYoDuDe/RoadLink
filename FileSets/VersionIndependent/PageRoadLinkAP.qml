import QtQuick 2
import com.victron.velib 1.0

MbPage {
    title: qsTr("RoadLink Fahrzeug-WLAN")
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
        MbItemText { text: qsTr("Eigenes DHCP und Fahrzeugnetz") }
        MbItemText { text: qsTr("Zugriffe aus fremden WLANs gesperrt") }
    }
}
