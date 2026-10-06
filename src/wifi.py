"""Native ConnMan WLAN inventory. Never export credential properties."""


def networks(bus, interface):
    import dbus
    manager = dbus.Interface(bus.get_object('net.connman', '/'), 'net.connman.Manager')
    result = []
    for path, props in manager.GetServices(timeout=5):
        if str(props.get('Type', '')) != 'wifi':
            continue
        ethernet = props.get('Ethernet', {})
        if str(ethernet.get('Interface', '')) != interface:
            continue
        result.append({
            'id': str(path), 'ssid': str(props.get('Name', 'Verstecktes WLAN')),
            'state': str(props.get('State', 'unknown')),
            'strength': int(props.get('Strength', 0)),
            'known': bool(props.get('Favorite', False)),
            'autoconnect': bool(props.get('AutoConnect', False)),
            'security': [str(value) for value in props.get('Security', [])],
        })
    return result
