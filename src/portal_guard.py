"""Independent portal watchdog; runtime retains its flock throughout cleanup.

The guarded runtime supplies PID/start-token aware operations and network
cleanup. Mutating children inherit the lock until they register their identity.
"""
import math
import signal


def supervise(controller, expires, read, alive, kill, cleanup, clock, sleep,
              heartbeat_timeout=20):
    now=clock()
    if (type(expires) not in (int,float) or not math.isfinite(expires)
            or expires>now+900):
        raise ValueError('Invalid portal watchdog deadline')
    last=None
    changed=now
    while alive(controller) and not read('stop'):
        now=clock()
        heartbeat=read('heartbeat')
        # Only a current, non-future monotonic heartbeat extends monitoring.
        if heartbeat!=last:
            try: value=float(heartbeat)
            except (TypeError,ValueError): value=float('-inf')
            if math.isfinite(value) and changed<=value<=now:
                last=heartbeat
                changed=value
        if now>=expires or now-changed>=heartbeat_timeout: break
        sleep(.2)
    # Prevent a controller from racing cleanup, then drain registered commands.
    if alive(controller): kill(controller,signal.SIGKILL)
    deadline=clock()+3
    while alive(controller) and clock()<deadline: sleep(.05)
    if alive(controller): raise RuntimeError('Portal controller could not stop')
    mutation=read('mutation') or {}
    if alive(mutation): kill(mutation,signal.SIGKILL)
    deadline=clock()+3
    while alive(mutation) and clock()<deadline: sleep(.05)
    if alive(mutation): raise RuntimeError('Portal mutation could not stop')
    cleanup()
