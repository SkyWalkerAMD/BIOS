"""Execute extracted RC3 P5/R2 x64 code against a shared recorded/synthetic BMC.

Serial schedules model UEFI TPL_CALLBACK notifications, NOT a real board. The
separate emulators share PCI/BMC state; this is not an interrupt scheduler test.
No real hardware or network is accessed. Inputs are extracted from the new CAP.
"""
from pathlib import Path
import hashlib, importlib.util, json, re, shutil, struct, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.dont_write_bytecode = True
R2 = ROOT/'analysis/hero_ipmi_r2'
P5 = ROOT/'analysis/hero_ipmi_p5'
sys.path.insert(0, str(R2))
import verify as r2
import verify_entry as entry
import pefile
from unicorn.x86_const import *

def sha(b): return hashlib.sha256(b).hexdigest()

META = json.loads((HERE/'container-verification.json').read_text())
assert META['passed']
INPUT = HERE/'runtime-input'
(INPUT/'USB/EFI/HERO').mkdir(parents=True, exist_ok=True)
for item in META['extracted_payloads']:
    data = (ROOT/item['extracted']).read_bytes()
    assert sha(data) == item['sha256']
    if item['guid'] == '89924765-f984-4ad3-839b-51fdce378d88':
        (INPUT/'USB/EFI/HERO/HeroIpmiR2.efi').write_bytes(data)
    elif item['guid'] == '261135b0-7b73-49c0-bcc8-2f9cf4eef19e':
        (INPUT/'HeroIpmiP5.efi').write_bytes(data)
shutil.copyfile(R2/'driver.map', INPUT/'driver.map')
r2.OUT = INPUT

FIELD = json.loads((ROOT/'analysis/hero_ipmi_p5_field_20261104/transactions.json').read_text())
RESPONSES = {}
for transaction in FIELD:
    netfn, command = (int(x,16) for x in transaction['netfn_cmd'].split('/'))
    tx = bytes([netfn << 2, command] + [int(x,16) for x in transaction['payload']])
    if tx != b'\x18\x01':
        RESPONSES[tx] = bytes.fromhex(transaction['response_hex'])

class SharedDevice(r2.Device):
    def response(self, tx):
        packet = bytes(tx)
        if packet in RESPONSES:
            self.packets.append(packet)
            return RESPONSES[packet]
        return super().response(tx)

class P5Machine(r2.Machine):
    def __init__(self, device, config, variables):
        super().__init__('success', full=True)
        self.dev = device
        self.config = config
        self.vars = variables
        pe = pefile.PE(str(INPUT/'HeroIpmiP5.efi'))
        pe.relocate_image(0x100000)
        self.u.mem_write(0x100000, bytes(0x100000))
        self.u.mem_write(0x100000, pe.get_memory_mapped_image())
        self.functions = {}
        for line in (P5/'driver.map').read_text().splitlines():
            m = re.match(r'\s+\d+:[0-9a-f]+\s+([\w.]+)\s+([0-9a-f]{16})', line, re.I)
            if m: self.functions[m[1]] = int(m[2],16)-0x140000000+0x100000
        self.w64(self.functions['gST'], self.st)

    def hook(self, u, addr, size, user):
        if self.stubs.get(addr) != 'MemWrite':
            return super().hook(u, addr, size, user)
        # The standalone R2 harness requires a durable lock whenever its own
        # OEM packet history is nonempty. P5 shares that history AFTER R2 has
        # legitimately cleared the lock. Validate P5's own writes separately.
        rsp = u.reg_read(UC_X86_REG_RSP)
        a,b,c,d = [u.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
        e,f = [self.r64(rsp+off) for off in (0x28,0x30)]
        assert a == self.pci and b == 0 and c == 1 and d in (0xe88,0xe8c) and e == 1 and self.config[4]&2
        before = len(self.dev.oem_packets)
        self.dev.write(d == 0xe8c, u.mem_read(f,1)[0])
        assert len(self.dev.oem_packets) == before, 'P5 must never send OEM commands'
        self.calls.append('MemWrite')
        u.reg_write(UC_X86_REG_RAX,0)
        for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):
            u.reg_write(reg,0xcccccccccccccccc)

def main():
    rows = []
    for schedule in ('P5_R2_P5', 'R2_P5', 'P5_R2_SECOND_READY_P5'):
        device = SharedDevice('success', full=True)
        rm = entry.EntryMachine()
        rm.dev = device
        assert rm.enter() == 0 and not device.packets
        pm = P5Machine(device, rm.config, rm.vars)
        states = []
        stages = ['P5','R2','READY','P5'] if 'SECOND' in schedule else schedule.split('_')
        for stage in stages:
            before = len(device.oem_packets)
            nv_before = len(rm.nv_writes)
            if stage == 'P5':
                status = pm.call('p1_collect')
                assert status == 0, pm.audit()
                assert len(device.oem_packets) == before and not pm.nv_writes
                assert 'BMC status, watchdog, LAN and SEL queried; read-only session.' in pm.audit()
                assert len(rm.nv_writes) == nv_before
            else:
                rm.signal()
                if stage == 'R2': assert len(device.oem_packets) == 4, rm.audit()
                else: assert len(device.oem_packets) == before
            assert int.from_bytes(rm.config[4:6],'little') == 0
            # ReplayDevice retains the last TX for inspection after completion.
            assert device.state == 0 and not device.obf, 'KCS transaction left in progress'
            states.append(dict(stage=stage, oem_total=len(device.oem_packets), pci_command=0))
        assert device.oem_packets == r2.base.EXPECTED_OEM
        assert 'HeroIpmiAttempt' not in rm.vars and 'HeroIpmiCfg' not in rm.vars
        assert 'READY_TO_BOOT_AUTO_ENABLED' in rm.audit()
        (HERE/f'{schedule}-r2.txt').write_text(rm.audit(),encoding='utf-8')
        (HERE/f'{schedule}-p5.txt').write_text(pm.audit(),encoding='utf-8')
        rows.append(dict(case=schedule,passed=True,stages=states,
            r2_pci_writes=rm.pci_writes,p5_pci_writes=pm.pci_writes, nv_writes=rm.nv_writes))
        print(schedule, 'PASS', flush=True)
    # New-boot behavior is essential now the core is part of the firmware.
    for case, configuration in [('already_initialized','missing'),('success','off'),
                                 ('prior_lock','missing'),('startup_c1','missing'),
                                 ('startup_ff','missing'),('version_unavailable','missing')]:
        rm = entry.EntryMachine(config=configuration, engine_case=case)
        if case == 'prior_lock': rm.vars['HeroIpmiAttempt'] = (3, b'\x01')
        assert rm.enter() == 0
        rm.signal()
        packets = len(rm.dev.packets)
        nv = len(rm.nv_writes)
        rm.signal()
        assert len(rm.dev.packets) == packets and len(rm.nv_writes) == nv
        assert not rm.dev.oem_packets
        assert int.from_bytes(rm.config[4:6],'little') == 0
        assert rm.elapsed_ms <= 45000
        if configuration == 'off': assert rm.vars['HeroIpmiCfg'][1][4] == 0
        if case == 'prior_lock': assert 'HeroIpmiAttempt' in rm.vars
        (HERE/f'boot-{case}-{configuration}.txt').write_text(rm.audit(),encoding='utf-8')
        rows.append(dict(case=f'boot_{case}_{configuration}', passed=True,
            no_oem=True, no_second_event_retry=True, poll_delay_ms=rm.elapsed_ms,
            pci_command_restored=True))
        print(case, configuration, 'PASS', flush=True)
    report = dict(passed=True, scope=__doc__, candidate_sha256=META['candidate_sha256'],
        r2_sha256=sha((INPUT/'USB/EFI/HERO/HeroIpmiR2.efi').read_bytes()),
        p5_sha256=sha((INPUT/'HeroIpmiP5.efi').read_bytes()), cases=rows, count=len(rows),
        scheduling_basis='Both automatic callbacks register TPL_CALLBACK=8; different manual TPL4 APIs are outside this test.',
        source='https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html#event-timer-and-task-priority-services',
        limitations=['Serial state-transition replay, not actual firmware interrupt scheduling.',
            'P5 p1_collect is exercised; native menu rendering is retained from RC2 hardware evidence.',
            'New onboard automatic initialization, cold/warm boots and FlashBack not demonstrated.'])
    (HERE/'runtime-verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('ALL PASS',len(rows))

if __name__ == '__main__': main()
