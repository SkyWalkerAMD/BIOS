"""Run compiled ACE discovery and attachment control flow in Unicorn.

Original ACE PE images are mapped. SMBIOS, protocol enumeration, allocations,
write permissions, variable-guard installation and HII services are fixtures.
This establishes bounded retries and rejection, not automatic Del/F2 coverage.
"""
from pathlib import Path
import hashlib
import json
import struct
import uuid

HERE = Path(__file__).resolve().parent
prefix = (HERE/'verify_adapter.py').read_text(encoding='utf8').split('\nchecks=[]', 1)[0]
ns = {'__file__': str(HERE/'verify_adapter.py')}
exec(compile(prefix, str(HERE/'verify_adapter.py'), 'exec'), ns)
for name in ('VM', 'U', 'R', 'TSE', 'SETUP', 'HEAP', 'STOP', 'symbols', 'q', 'd'):
    globals()[name] = ns[name]
ERR = lambda n: (1 << 63) | n
LOCATE, HANDLE, FREE, TIMER = [STOP + n for n in (0x1100, 0x1110, 0x1120, 0x1130)]
BROWSER = uuid.UUID('b9d4c360-bcfb-4f9b-9298-53c136982258').bytes_le


class DiscoveryVM(VM):
    def __init__(self):
        self.browser_ready = True
        self.browser_owner_wrong = False
        self.images_ready = True
        self.stage_on_locate = None
        self.fail_allocations = 0
        self.allocations = 0
        self.patch_failure = None
        self.patches = []
        self.timer_cancels = 0
        self.inventory = [0xabc1, 0xabc2]
        super().__init__()
        self.u.mem_write(self.bs+0x138, q(LOCATE))
        self.u.mem_write(self.bs+0x98, q(HANDLE))
        self.u.mem_write(self.bs+0x48, q(FREE))
        self.u.mem_write(self.bs+0x58, q(TIMER))
        for target in (LOCATE, HANDLE, FREE, TIMER):
            self.u.hook_add(U.UC_HOOK_CODE, self.hook, begin=target, end=target)
        self.u.mem_write(symbols['discovery_timer'], q(0x1234))
        self.u.mem_write(TSE+0x82628, d(3))
        self.setup_inventory()

    def argn(self, index):
        if index < 4:
            return self.arg(index)
        return self.getq(self.u.reg_read(R.UC_X86_REG_RSP)+40+(index-4)*8)

    def hook(self, u, address, size, data):
        if address == LOCATE:
            if not self.images_ready:
                self.ret(ERR(14)); return
            u.mem_write(HEAP+0x1c0000, b''.join(q(h) for h in self.inventory))
            u.mem_write(self.arg(3), q(len(self.inventory)))
            u.mem_write(self.argn(4), q(HEAP+0x1c0000))
            self.ret(0); return
        if address == HANDLE:
            records = {0xabc1: HEAP+0x1c1000, 0xabc2: HEAP+0x1c2000, 0xabc3: HEAP+0x1c1000}
            if self.arg(0) not in records:
                self.ret(ERR(14)); return
            u.mem_write(self.arg(2), q(records[self.arg(0)])); self.ret(0); return
        if address == FREE:
            self.ret(0); return
        if address == TIMER:
            assert self.arg(0) == 0x1234 and self.arg(1) == 0
            self.timer_cancels += 1; self.ret(0); return
        if address == STOP+0x110:
            if self.browser_ready and bytes(u.mem_read(self.arg(0), 16)) == BROWSER:
                u.mem_write(self.arg(2), q(HEAP+0x1b0000 if self.browser_owner_wrong else TSE+0x6b528))
                if self.stage_on_locate is not None:
                    u.mem_write(TSE+0x82628, d(self.stage_on_locate))
                self.ret(0)
            else:
                self.ret(ERR(14))
            return
        if address == STOP+0x100:
            self.allocations += 1
            if self.fail_allocations:
                self.fail_allocations -= 1; self.ret(ERR(9)); return
        if address == symbols['patch_memory']:
            self.patches.append(self.arg(0))
            if self.arg(0) == self.patch_failure:
                self.ret(0); return
        super().hook(u, address, size, data)

    def setup_inventory(self, product='Pro WS W790-ACE', version='1904'):
        def record(kind, length, strings):
            raw = bytearray(length); raw[0] = kind; raw[1] = length
            if kind == 0: raw[5] = 1
            if kind == 2: raw[4] = 1; raw[5] = 2
            return bytes(raw) + b'\0'.join(s.encode('ascii') for s in strings) + b'\0\0'
        table = HEAP+0x1d0000; entry = table+0x1000; ct = table+0x2000
        raw = record(0, 24, [version])+record(2, 15, ['ASUSTeK COMPUTER INC.', product])+record(127, 4, [])
        self.u.mem_write(table, raw)
        ep = bytearray(24); ep[:5] = b'_SM3_'; ep[6] = 24; ep[7:11] = bytes([3, 6, 0, 1])
        struct.pack_into('<IQ', ep, 12, len(raw), table); ep[5] = (-sum(ep)) & 255
        self.u.mem_write(entry, bytes(ep))
        self.u.mem_write(ct, uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+q(entry))
        self.u.mem_write(self.st+0x68, q(1)+q(ct))
        for offset, base, image_size, guid in [
            (0x1000, TSE, 0xa2000, 'b1da0adf-4f77-4070-a88e-bffe1c60529a'),
            (0x2000, SETUP, 0x1a4000, '899407d7-99fe-43d8-9a21-79ec328cac21')]:
            li = HEAP+0x1c0000+offset; path = li+0x100
            self.u.mem_write(li+0x20, q(path)); self.u.mem_write(li+0x40, q(base)+q(image_size))
            self.u.mem_write(path, b'\x04\x06\x14\0'+uuid.UUID(guid).bytes_le+b'\x7f\xff\x04\0')

    def discover(self):
        self.call(symbols['discover'], 0, 0)

    def value(self, name):
        return self.getd(symbols[name])


checks = []
def check(name, value):
    assert value, name
    checks.append(name)

v = DiscoveryVM(); v.browser_ready = False; v.discover()
check('missing browser publication performs no attach or target writes', v.allocations == 0 and not v.patches and v.value('attempted') == 0)
v.browser_ready = True; v.discover()
check('later browser publication permits one successful attachment', v.value('platform_ready') == 1 and v.allocations == 1 and v.timer_cancels == 1)

v = DiscoveryVM(); v.images_ready = False; v.discover()
check('missing image inventory is deferred before allocation', v.allocations == 0 and v.value('attempted') == 0)
v.images_ready = True; v.discover()
check('later image inventory can attach', v.value('platform_ready') == 1)

v = DiscoveryVM(); v.browser_owner_wrong = True; v.discover()
check('foreign FormBrowser2 does not establish OEM readiness', v.allocations == 0 and not v.patches)
v.browser_owner_wrong = False; v.discover()
check('exact original interface can subsequently attach', v.value('platform_ready') == 1)
for offset in (0x6b528, 0x6b530):
    v = DiscoveryVM(); v.u.mem_write(TSE+offset, q(STOP+0x3000)); v.discover()
    check('wrong original browser method rejected at '+hex(offset), v.allocations == 0 and not v.patches)

v = DiscoveryVM(); v.u.mem_write(TSE+0x82628, d(5)); v.discover()
check('running native browser is never hot patched', not v.patches and v.allocations == 0 and v.value('attempted') == 0)
v.u.mem_write(TSE+0x82628, d(7)); v.discover()
check('later safe window can attach without claiming first visit protected', v.value('platform_ready') == 1)

v = DiscoveryVM(); v.stage_on_locate = 5; v.discover()
check('browser becoming active during LocateProtocol is deferred', v.allocations == 0 and not v.patches)
v.stage_on_locate = None; v.u.mem_write(TSE+0x82628, d(7)); v.discover()
check('later safe discovery after publication race attaches', v.value('platform_ready') == 1)

v = DiscoveryVM(); v.fail_allocations = 1; v.discover()
check('allocation failure before publication remains retryable', v.value('attempted') == 0 and not v.patches and v.value('attach_attempts') == 1)
v.discover()
check('next pre-publication attempt succeeds', v.value('platform_ready') == 1 and v.value('attach_attempts') == 2)

v = DiscoveryVM(); v.fail_allocations = 9
for _ in range(8): v.discover()
check('allocation failure is bounded at three attempts', v.allocations == 3 and v.value('attach_attempts') == 3 and v.value('attempted') == 1 and not v.patches)
check('terminal pre-publication failures cancel discovery timer once', v.timer_cancels == 1)

v = DiscoveryVM(); v.patch_failure = TSE+0x6af78; v.discover(); before = len(v.patches)
check('failure after publication is terminal', v.value('attempted') == 1 and v.value('platform_ready') == 0)
v.patch_failure = None; v.discover()
check('terminal publication failure is never automatically retried', len(v.patches) == before and v.value('attach_attempts') == 1)

v = DiscoveryVM(); v.inventory = [0xabc1, 0xabc2, 0xabc3]; v.discover()
check('duplicate AMITSE owner is rejected without writes', v.allocations == 0 and not v.patches and v.value('attempted') == 0)
v.inventory = [0xabc1, 0xabc2]; v.discover()
check('fresh unique inventory can subsequently attach', v.value('platform_ready') == 1)

for product, version in [('Pro WS W790E-SAGE SE', '1904'), ('Pro WS W790-ACE', '2003'), ('Pro WS W790-ACE X', '1904')]:
    v = DiscoveryVM(); v.setup_inventory(product, version); v.discover()
    check('wrong target rejected: '+product+'/'+version, not v.patches and v.allocations == 0 and v.value('matching_board') == 0)
v = DiscoveryVM(); v.u.mem_write(symbols['boot_services_ended'], d(1)); v.discover()
check('retired discovery performs no allocations or patches', v.allocations == 0 and not v.patches)

report = {'status': 'PASS', 'checks': len(checks), 'check_names': checks,
          'driver_sha256': hashlib.sha256((HERE/'build/AiTweakerLock1904.efi').read_bytes()).hexdigest(),
          'source_sha256': {n: hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in ('entry.c', 'platform.c', 'verify_discovery.py')},
          'limits': [__doc__, 'The variable guard and memory write services are stubs; their independent failure matrices are separate.',
                     'Stage5 deferral deliberately leaves an already-running first native visit unpatched; this is not a permanent cold-entry solution.']}
(HERE/'build/discovery_regression.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
print(json.dumps({'status': report['status'], 'checks': report['checks'], 'driver_sha256': report['driver_sha256']}))
