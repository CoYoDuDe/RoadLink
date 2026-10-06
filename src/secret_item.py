"""Write-only BusItem command: never publishes a submitted credential."""
import dbus.service
from vedbus import VeDbusItemExport


class SecretItem(VeDbusItemExport):
    @dbus.service.method('com.victronenergy.BusItem', in_signature='v', out_signature='i')
    def SetValue(self, value):
        if not self._writeable or not isinstance(value, str):
            return 1
        if not value:  # cancelling the native editor restores its empty value
            return 0
        # Unlike a normal BusItem, do not assign _value or emit the credential
        # in PropertiesChanged/ItemsChanged. GetValue/GetItems remain empty.
        return 0 if self._onchangecallback(self._path, str(value)) else 2
