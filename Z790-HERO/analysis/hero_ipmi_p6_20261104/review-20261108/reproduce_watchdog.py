"""Independent interruption replay of the shipped P6 candidate's x64 code.

No real device/network. A simulated power interruption occurs after the BMC
accepts Reset Watchdog but before firmware receives/commits final status.
"""
from pathlib import Path
import copy, hashlib, importlib.util, json, sys, traceback
HERE=Path(__file__).resolve().parent;BASE=HERE.parent;ROOT=BASE.parents[1]
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('p6runtime',BASE/'verify_runtime.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)

class PowerLoss(Exception):pass

def main():
    m=runtime.Machine(runtime.cfg(enabled=1,minutes=1,action=1))
    m.boot()
    assert not m.dev.sim.wdt[0]&0x40
    def loss(f,c,p):
        if (f,c)==(6,0x22):
            reply=m.dev.sim.model(f,c,p)
            assert m.dev.sim.wdt[0]&0x40
            raise PowerLoss('Reset accepted; host reset before transaction completion')
    m.dev.fault=loss
    try:
        m.call('p6_start_os_watchdog')
        raise AssertionError('interruption did not occur')
    except PowerLoss:pass
    variables=copy.deepcopy(m.vars)
    pending=variables['HeroIpmiState'][1]
    assert runtime.pending(pending) and int.from_bytes(pending[16:20],'little')==6
    # Deliberately model a healthy idle KCS on restart: the refusal below is
    # independent of whether the real card retains an interrupted KCS state.
    fresh=runtime.Device()
    fresh.sim.wdt=bytearray(m.dev.sim.wdt)
    n=runtime.Machine(variables=variables,device=fresh)
    assert n.call('p6_seed_settings')==0
    n.call('p6_stop_os_watchdog')
    no_stop=bool(fresh.sim.wdt[0]&0x40) and len(fresh.packets)==0
    result={
      'case':'reset_after_wdt_start_before_final_journal_then_setup',
      'driver_sha256':hashlib.sha256((BASE/'HeroIpmiP6.efi').read_bytes()).hexdigest(),
      'settings_source_sha256':hashlib.sha256((BASE/'source/settings.c').read_bytes()).hexdigest(),
      'seed_status':0,'pending_phase':6,'pending_blocked':1,
      'restart_device_assumption':'KCS healthy/idle; OS Load BMC watchdog retained and running',
      'after_setup_stop_callback':{'bmc_packets':len(fresh.packets),'watchdog_running':bool(fresh.sim.wdt[0]&0x40)},
      'reproduced':no_stop,
      'scope':'Actual x64 candidate instructions against synthetic UEFI/BMC. No hardware timing claim.',
      'recommendation':'Keep normal retry blocked but permit bounded recovery stop of matching OS Load timer before returning to Setup; verify timer state and preserve uncertainty journal.'}
    (HERE/'pending-watchdog-replay.json').write_text(json.dumps(result,indent=2)+'\n')
    (HERE/'pending-watchdog-first-boot.txt').write_text(m.audit())
    (HERE/'pending-watchdog-next-boot.txt').write_text(n.audit())
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
