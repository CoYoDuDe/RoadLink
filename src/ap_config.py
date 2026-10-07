"""Validated WPA2/CCMP AP configuration; never permits an open vehicle AP."""
import hashlib
import ipaddress
import re


def hostapd(interface, ssid, passphrase, channel=6):
    if not re.fullmatch(r'ap[a-zA-Z0-9_]{1,12}', interface):
        raise ValueError('AP interface must be excluded from ConnMan ownership')
    if not isinstance(ssid, str) or not 1 <= len(ssid.encode('utf-8')) <= 32:
        raise ValueError('SSID must contain 1 to 32 UTF-8 bytes')
    if not isinstance(passphrase, str) or not 8 <= len(passphrase) <= 63:
        raise ValueError('WPA2 passphrase must contain 8 to 63 ASCII characters')
    if any(ord(c) < 32 or ord(c) > 126 for c in passphrase):
        raise ValueError('WPA2 passphrase must contain printable ASCII only')
    if isinstance(channel, bool) or channel not in (1, 6, 11):
        raise ValueError('Unsupported 2.4 GHz channel')
    # Hex SSID avoids newline/config injection; derived PSK avoids plaintext storage.
    # A PSK is still a credential and the resulting file must remain mode 0600.
    psk = hashlib.pbkdf2_hmac('sha1', passphrase.encode('ascii'), ssid.encode('utf-8'), 4096, 32).hex()
    return ('interface={}\ndriver=nl80211\nssid2={}\nhw_mode=g\nchannel={}\n'
            'auth_algs=1\nwpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n'
            'wpa_psk={}\nap_isolate=1\n').format(interface, ssid.encode().hex(), channel, psk)


def choose_subnet(occupied, preferred='172.27.88.0/24'):
    networks = [ipaddress.ip_network(item, strict=False) for item in occupied]
    candidates = [preferred] + ['172.27.{}.0/24'.format(i) for i in range(89, 120)]
    for value in candidates:
        candidate = ipaddress.ip_network(value)
        if candidate.version != 4 or candidate.prefixlen != 24 or not candidate.is_private:
            raise ValueError('AP subnet must be private IPv4 /24')
        if not any(n.version == 4 and n.prefixlen > 0 and candidate.overlaps(n) for n in networks):
            return str(candidate)
    raise ValueError('No non-overlapping AP subnet available')


def isolated_dhcp(interface, subnet, vpn_dns=None):
    if not re.fullmatch(r'ap[a-zA-Z0-9_]{1,12}', interface):
        raise ValueError('Invalid AP interface')
    net = ipaddress.ip_network(subnet)
    if net.version != 4 or net.prefixlen != 24 or not net.is_private:
        raise ValueError('Invalid AP subnet')
    # Only the guarded AP runtime may advertise these after routing is active.
    options = 'dhcp-option=3\ndhcp-option=6\n'
    if vpn_dns is not None:
        dns = ipaddress.ip_address(vpn_dns)
        if (dns.version != 4 or not (dns.is_global or any(dns in ipaddress.ip_network(network)
                for network in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')))
                or dns.is_multicast or dns.is_reserved or dns in net):
            raise ValueError('VPN DNS must be usable IPv4 outside the AP subnet')
        options = 'dhcp-option=3,{}\ndhcp-option=6,{}\n'.format(net[1], dns)
    return ('interface={}\nbind-interfaces\nport=0\nno-resolv\nno-hosts\n'
            'dhcp-range={},{},255.255.255.0,{}\n{}'
            'dhcp-leasefile=/run/roadlink/ap.leases\n').format(
                interface, net[20], net[200], '1h' if vpn_dns else '1m', options)
