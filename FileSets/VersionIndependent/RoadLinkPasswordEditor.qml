import QtQuick 2
import com.victron.velib 1.0
MbEditBox {
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
