"""Try an alternate uplink promptly, while respecting public enrollment limits."""


class EnrollmentSchedule:
    def __init__(self):
        self.tried = set()
        self.retry_at = 0

    def finished(self, now):
        self.retry_at = now + 900

    def choose(self, native, bootstrap_ready, now):
        if now >= self.retry_at:
            self.tried.clear()
        if len(self.tried) >= 2:
            return None
        if native and native not in self.tried:
            return native
        if bootstrap_ready and 'disabledrlwan' not in self.tried:
            return 'disabledrlwan'
        return None

    def started(self, interface):
        self.tried.add(interface)
