"""Drain old forwarding first, then AP/WLAN, before starting a new mode.

The daemon supplies live process/guard/journal and kernel checks. No timeout
can turn unfinished cleanup into authorization to start a different mode.
"""


class Barrier:
    def __init__(self, stop, busy, clear):
        self.stop, self.busy, self.clear = stop, busy, clear
        self.current = None
        self.phase = None

    def step(self, wanted):
        if wanted not in ('vpn', 'direct', 'off'):
            raise ValueError('Invalid transport mode')
        if self.phase is None and self.current == wanted:
            return True
        if self.phase is None:
            self.phase = 0
        groups = (('direct', 'vpn'), ('ap', 'wan'))
        while self.phase < len(groups):
            group = groups[self.phase]
            for name in group:
                self.stop(name)
            if any(self.busy(name) for name in group):
                return False
            self.phase += 1
        if not self.clear():
            return False
        # wanted is read anew during every step; an intervening edit never
        # launches a superseded mode after the old services finish draining.
        self.current, self.phase = wanted, None
        return True
