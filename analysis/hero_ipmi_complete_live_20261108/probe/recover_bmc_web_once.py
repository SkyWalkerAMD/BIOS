"""One guarded BMC cold reset after persistent HTTPS failure; no host power action.

The known .71 BMC identity, LAN MAC, and stopped watchdog must match before
the single standard 06/02 command. No automatic retransmission or replay.
"""
from pathlib import Path
import getpass
import importlib.util
import json
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fan_get_guard', HERE / 'fan_mapping_get.py')
fan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fan)
base = fan.base
base.MAX_COMMANDS = 4
identity_ok = mac_ok = watchdog_ok = False


def allow(netfn, command, data=(), sensor_ids=()):
    b = bytes(data)
    if (netfn, command) == (6, 1) and not b:
        return
    if identity_ok and (netfn, command) == (12, 2) and b == bytes([1, 5, 0, 0]):
        return
    if identity_ok and mac_ok and (netfn, command) == (6, 0x25) and not b:
        return
    if identity_ok and mac_ok and watchdog_ok and (netfn, command) == (6, 2) and not b:
        return
    raise base.PolicyError('Command outside observed BMC recovery sequence')


base.validate_read = allow


def worker():
    global identity_ok, mac_ok, watchdog_ok
    connection = None
    reset_requested = False
    try:
        password = json.loads(sys.stdin.buffer.readline(4097))
        if not isinstance(password, str) or not 0 < len(password) <= 128:
            raise base.PolicyError('Credential input')
        base.verify_dependencies()
        Session = fan.admin_session_class()
        connection = Session(bmc=base.HOST, userid=base.USER, password=password,
                             port=623, privlevel=4, keepalive=False)
        password = None
        if connection.ipmiversion != 2.0 or connection.privlevel != 4:
            raise base.PolicyError('Authenticated ADMIN LAN+ required')
        connection.reads_enabled = True
        collector = base.Collector(connection, base.emit)
        identity_ok = collector.read('device_id', 6, 1) == bytes.fromhex('2081010302bf3f0a0093100d000000')
        if not identity_ok:
            raise base.ProbeStop('identity_mismatch')
        mac = collector.read('lan1_mac', 12, 2, [1, 5, 0, 0])
        mac_ok = mac is not None and len(mac) == 7 and mac[1:] == bytes.fromhex('b082e2ac382c')
        if not mac_ok:
            raise base.ProbeStop('target_MAC_mismatch')
        watchdog = collector.read('watchdog', 6, 0x25)
        watchdog_ok = watchdog is not None and len(watchdog) == 8 and not watchdog[0] & 0x40
        if not watchdog_ok:
            raise base.ProbeStop('watchdog_not_confirmed_stopped')
        base.emit(dict(type='bmc_cold_reset_once', netfn=6, command=2, retry=False,
                       note='Not chassis control, not host reset, no firmware or LAN configuration change'))
        reset_requested = True
        collector.read('bmc_cold_reset_reply', 6, 2)
        return 0 if collector.last_completion == 0 else 2
    except Exception as e:
        base.emit(dict(type='stopped', exception_type=type(e).__name__, reset_requested=reset_requested,
                       reason=str(e) if isinstance(e, base.ProbeStop) else 'transport_or_policy'))
        return 2
    finally:
        password = None
        # A reset invalidates the session; do not send more traffic or retry.
        if connection is not None and not reset_requested:
            try:
                connection.logout()
            except Exception:
                pass


if '--worker' in sys.argv:
    raise SystemExit(worker())

attempt = HERE / 'bmc-web-recovery-attempt.json'
result = HERE / 'bmc-web-recovery-result.json'
if attempt.exists() or result.exists():
    raise SystemExit('Recovery has already been attempted; inspect evidence instead of replaying.')
base.verify_dependencies()
print('One BMC cold reset on .71 after exact Device ID, MAC and stopped watchdog checks.')
password = getpass.getpass('IPMI password (not saved): ')
secret = (json.dumps(password) + '\n').encode()
password = None
with attempt.open('x', encoding='utf-8') as f:
    json.dump(dict(target=base.HOST, started_utc=base.utc_now(), reason='HTTPS refused persistently; standard IPMI responds'), f)
code, timeout, raw, stderr_count = base.bounded_child(
    [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()), '--worker'], secret, 60)
secret = None
events = []
for line in raw.decode('utf-8', errors='replace').splitlines():
    try:
        item = json.loads(line)
        if isinstance(item, dict) and 'type' in item:
            events.append(item)
    except ValueError:
        pass
with result.open('x', encoding='utf-8') as f:
    json.dump(dict(target=base.HOST, finished_utc=base.utc_now(), return_code=code,
                   hard_timeout=timeout, stderr_bytes_not_saved=stderr_count, events=events), f, indent=2)
print(json.dumps(dict(file=str(result), return_code=code, hard_timeout=timeout, events=len(events))))
raise SystemExit(code)
