"""Native provider settings; both profiles and the private key stay local."""
from vpn_providers import state, select, save_profile
from wireguard import ensure_public_key
import subprocess


FIELDS = {'Endpoint': ('endpoint', ''), 'Port': ('port', 51820),
          'ServerKey': ('public_key', ''), 'Address': ('address', ''),
          'DNS': ('dns', ''), 'MTU': ('mtu', 1380)}


def custom_config(values):
    from vpn_config import validate
    result = {'enabled': True, 'provider': 'custom'}
    for name, (field, default) in FIELDS.items():
        value = values[name]
        if name in ('Port', 'MTU'):
            if isinstance(value, bool) or not str(value).isdigit():
                raise ValueError('Invalid numeric VPN field')
            value = int(value)
        else:
            value = str(value).strip()
        result[field] = value
    return validate(result)


def install(service):
    from secret_item import SecretItem
    try:
        value = state()
        status = 'DNSmith' if value['selected'] == 'dnsmith' else 'Eigener VPN'
    except (ValueError, KeyError, OSError):
        value = {'selected': 'dnsmith', 'profiles': {}}
        status = 'VPN-Konfiguration ungueltig'
    service.add_path('/VPN/ProviderStatus', status)
    service.add_path('/VPN/ClientPublicKey', '')
    for name, (field, default) in FIELDS.items():
        service.add_path('/VPN/Custom/' + name, value['profiles'].get('custom', {}).get(field, default),
                         writeable=True)

    def choose(path, value):
        if value not in (0, 1):
            return False
        try:
            select('dnsmith' if value else 'custom')
            current = state()
            for name, (field, default) in FIELDS.items():
                service['/VPN/Custom/' + name] = current['profiles'].get('custom', {}).get(field, default)
            service['/VPN/ProviderStatus'] = ('DNSmith ausgewaehlt' if value else
                'Eigener VPN ausgewaehlt' if 'custom' in current['profiles'] else 'Eigenen VPN einrichten')
            return True
        except (ValueError, KeyError, OSError):
            service['/VPN/ProviderStatus'] = 'Anbieterwechsel fehlgeschlagen'
            return False

    def save(path, value):
        if value != 'save':
            return False
        try:
            config = custom_config({name: service['/VPN/Custom/' + name] for name in FIELDS})
            if not save_profile(config):
                raise ValueError('Custom VPN is not selected')
            service['/VPN/ProviderStatus'] = 'Eigener VPN gespeichert'
            return True
        except (ValueError, KeyError, OSError):
            service['/VPN/ProviderStatus'] = 'VPN-Felder pruefen'
            return False

    service.add_path('/VPN/UseDNSmith', int(value['selected'] == 'dnsmith'), writeable=True,
                     onchangecallback=choose)
    service.add_path('/VPN/Custom/Save', '', writeable=True, itemtype=SecretItem, onchangecallback=save)

    def public_key(path, value):
        if value != 'show':
            return False
        try:
            service['/VPN/ClientPublicKey'] = ensure_public_key()
            return True
        except (ValueError, OSError, subprocess.SubprocessError):
            service['/VPN/ProviderStatus'] = 'Geraeteschluessel nicht verfuegbar'
            return False
    service.add_path('/VPN/ShowPublicKey', '', writeable=True, itemtype=SecretItem, onchangecallback=public_key)
