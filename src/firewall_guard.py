"""Bind every forwarding controller to one validated private policy snapshot."""
import firewall_config


class Changed(RuntimeError):
    """Expected policy handover; controllers drain without an error traceback."""


def snapshot():
    return firewall_config.read()


def require(expected):
    if snapshot() != firewall_config.validate(expected):
        raise Changed('Firewall policy changed; controller must drain')


def matches(config):
    try:
        return snapshot() == firewall_config.validate(config.get('firewall', firewall_config.DEFAULT))
    except (ValueError, TypeError, OSError):
        return False
