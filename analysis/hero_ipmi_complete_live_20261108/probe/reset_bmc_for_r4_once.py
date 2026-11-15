"""One BMC restart for the R4 fresh-initialization test; never host power control.

This intentionally discards volatile BMC sensor initialization. The validated
R4 test media must be ready before use. Identity and the known sensor settings
are checked immediately before the one reset; an uncertain reply is not retried.
"""
from pathlib import Path
import getpass
import importlib.util
import json
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fixed_fan_get', HERE / 'fan_mapping_get.py')
fan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fan)
base = fan.base
base.MAX_COMMANDS = 10


class Gate:
    def __init__(self):
        self.armed = False
        self.sent = False

    def validate(self, netfn, command, data=(), sensor_ids=()):
        b = bytes(data)
        if (netfn, command) in ((6, 1), (6, 0x25)) and not b:
            return
        if (netfn, command) == (12, 2) and b == b'\x01\x05\x00\x00':
            return
        if (netfn, command) == (4, 0x2d) and b in (b'\xfb', b'\x20'):
            return
        if (netfn, command) == (0x30, 0x9a) and b in (b'\x00\x00', b'\x01\x00', b'\x02\x00', b'\x03\x00'):
            return
        if self.armed and not self.sent and (netfn, command) == (6, 2) and not b:
            self.armed = False
            self.sent = True
            return
        raise base.PolicyError('Outside single BMC restart and fixed preflight reads')


def preflight(c):
    if c.read('device_id', 6, 1) != bytes.fromhex('2081010302bf3f0a0093100d000000'):
        raise base.ProbeStop('identity_mismatch')
    mac = c.read('lan1_mac', 12, 2, [1, 5, 0, 0])
    if mac is None or len(mac) != 7 or mac[1:] != bytes.fromhex('b082e2ac382c'):
        raise base.ProbeStop('MAC_mismatch')
    wd = c.read('watchdog', 6, 0x25)
    if wd is None or len(wd) != 8 or wd[0] & 0x40:
        raise base.ProbeStop('watchdog_not_confirmed_stopped')
    if c.read('version_error', 4, 0x2d, [0xfb]) != bytes.fromhex('00c00080'):
        raise base.ProbeStop('initialized_baseline_changed')
    reading = c.read('known_cha1_reading', 4, 0x2d, [0x20])
    if reading is None or len(reading) != 4 or not reading[0] or reading[1:] != bytes.fromhex('c0c000'):
        raise base.ProbeStop('known_fan_reading_changed')
    maps = tuple(c.read('fan_table_' + str(i), 0x30, 0x9a, [i, 0]) for i in range(4))
    expected = (b'\x00', bytes([0, 0, 0x62]) + bytes(12), bytes(15), bytes([1]) * 15)
    if maps != expected:
        raise base.ProbeStop('fan_control_baseline_changed')


def worker():
    connection = None
    gate = Gate()
    reset_requested = False
    try:
        password = json.loads(sys.stdin.buffer.readline(4097))
        if not isinstance(password, str) or not 0 < len(password) <= 128:
            raise base.PolicyError('Credential input')
        base.verify_dependencies()
        base.validate_read = gate.validate
        Session = fan.admin_session_class()
        connection = Session(bmc=base.HOST, userid=base.USER, password=password, port=623,
                             privlevel=4, keepalive=False)
        password = None
        if connection.ipmiversion != 2.0 or connection.privlevel != 4:
            raise base.PolicyError('Authenticated ADMIN LAN+ required')
        connection.reads_enabled = True
        collector = base.Collector(connection, base.emit)
        preflight(collector)
        gate.armed = True
        base.emit(dict(type='bmc_restart_once_for_r4', netfn=6, command=2, retry=False,
                       scope='BMC only; volatile initialization intentionally cleared; no chassis command'))
        reset_requested = True
        collector.read('bmc_cold_reset_reply', 6, 2)
        return 0 if gate.sent and collector.last_completion == 0 else 2
    except Exception as e:
        base.emit(dict(type='stopped', exception_type=type(e).__name__, reset_requested=reset_requested,
                       reason=str(e) if isinstance(e, base.ProbeStop) else 'transport_or_policy'))
        return 2
    finally:
        password = None
        if connection is not None and not reset_requested:
            try:
                connection.logout()
            except Exception:
                pass


def main():
    if sys.argv[1:] == ['--worker']:
        return worker()
    if sys.argv[1:] != ['--fresh-r4-test']:
        raise SystemExit('Use --fresh-r4-test only after the validated R4 media is ready.')
    attempt = HERE / 'bmc-r4-fresh-attempt.json'
    result = HERE / 'bmc-r4-fresh-result.json'
    if attempt.exists() or result.exists():
        raise SystemExit('Already attempted. Inspect evidence; no replay.')
    base.verify_dependencies()
    print('One BMC restart for fresh R4 initialization. Host power is not changed.')
    password = getpass.getpass('IPMI password (not saved): ')
    if not password:
        raise SystemExit('Empty credential')
    secret = (json.dumps(password) + '\n').encode()
    password = None
    with attempt.open('x', encoding='utf-8') as f:
        json.dump(dict(target=base.HOST, started_utc=base.utc_now(),
                       reason='Validate fresh BMC sensor initialization by the frozen R4 driver'), f)
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
    return code


if __name__ == '__main__':
    raise SystemExit(main())
