"""Actual new P6 PE: exact lengths, unchanged journal and width-preserving writes.
Every EFI/BMC action is a RAM fixture. Never accesses a real machine.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys,zlib
HERE=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('settings21_runtime',HERE/'verify_runtime.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
rows=[]
def run(name,fn):fn();rows.append(name)
def no_mutation(m):assert not m.nv_writes and not m.dev.packets and not m.pci_writes
def valid_journal(data):
 assert len(data)==144 and struct.unpack_from('<III',data)==(0x36504948,1,144)
 copy=bytearray(data);stored=struct.unpack_from('<I',data,12)[0];copy[12:16]=bytes(4);assert zlib.crc32(copy)==stored
 assert data[45:56]==bytes(11) and data[77:88]==bytes(11)
def safe(n):
 m=v.Machine(v.cfg()[:n]);m.u.mem_write(m.functions['boot_config'],b'\xA5'*32)
 assert m.call('efi_main',v.IMAGE,m.st)==0
 assert bytes(m.u.mem_read(m.functions['boot_config'],32))==v.cfg()
 for cb in ('on_setup','on_ready','on_before','on_after','on_shell'):m.call(cb,0,0)
 no_mutation(m);assert len(m.vars['HeroIpmiSettings'][1])==n and 'HeroIpmiState' not in m.vars
 assert m.call('unload',v.IMAGE)==v.ERR(15)
for n in (21,32):run('default length '+str(n)+' normalizes zero + no writes',lambda n=n:safe(n))
def invalid_length(n):
 m=v.Machine((v.cfg()+bytes(32))[:n]);assert m.call('p6_seed_settings')==v.ERR(33)
 for cb in ('p6_apply_settings','p6_start_os_watchdog','p6_stop_os_watchdog'):m.call(cb)
 no_mutation(m)
for n in (0,1,20,22,23,30,31,33,64):run('reject settings length '+str(n),lambda n=n:invalid_length(n))
def bad_attr(n):
 m=v.Machine(variables={'HeroIpmiSettings':(7,v.cfg()[:n])});assert m.call('p6_seed_settings')==v.ERR(33);m.call('p6_apply_settings');no_mutation(m)
for n in (21,32):run('reject attributes '+str(n),lambda n=n:bad_attr(n))
def missing():
 m=v.Machine();m.boot();assert m.nv_writes==[('HeroIpmiSettings',v.cfg().hex())] and not m.dev.packets and 'HeroIpmiState' not in m.vars
run('missing keeps previous 32-byte seed only',missing)
def short_invalid(field,value):
 p=bytearray(v.cfg()[:21]);p[field]=value;m=v.Machine(bytes(p));assert m.call('p6_seed_settings')==v.ERR(33);m.call('p6_apply_settings');no_mutation(m)
for f,val in ((0,3),(1,12),(2,2),(3,0),(3,31),(4,4),(5,3),(6,3),(7,3),(20,2)):
 run('reject21 field '+str((f,val)),lambda f=f,val=val:short_invalid(f,val))
def bad_reserved():
 p=bytearray(v.cfg());p[31]=1;m=v.Machine(bytes(p));assert m.call('p6_seed_settings')==v.ERR(33);m.call('p6_apply_settings');no_mutation(m)
run('reject32 nonzero reserved',bad_reserved)
def width_change(n):
 m=v.Machine(v.cfg()[:n]);assert m.call('p6_seed_settings')==0
 m.vars['HeroIpmiSettings']=(3,v.cfg()[:32 if n==21 else 21]);m.call('p6_apply_settings');no_mutation(m)
for n in (21,32):run('same bytes different stored width blocks until next boot '+str(n),lambda n=n:width_change(n))
def retry(n):
 m=v.Machine(v.cfg(retry=1)[:n]);m.boot()
 writes=[bytes.fromhex(x[1]) for x in m.nv_writes if x[0]=='HeroIpmiSettings'];assert writes==[v.cfg()[:n]]
 assert not m.dev.packets and len(m.vars['HeroIpmiSettings'][1])==n
 valid_journal(m.vars['HeroIpmiState'][1])
for n in (21,32):run('retry consume preserves stored width '+str(n),lambda n=n:retry(n))
def erase(n):
 m=v.Machine(v.cfg(erase=1)[:n]);m.boot();assert m.dev.sim.clear_started==1
 writes=[bytes.fromhex(x[1]) for x in m.nv_writes if x[0]=='HeroIpmiSettings'];assert writes==[v.cfg()[:n]]
 valid_journal(m.vars['HeroIpmiState'][1]);m.no_leak()
 for _ in range(2):m=m.next_boot();m.boot();assert m.dev.sim.clear_started==1 and len(m.vars['HeroIpmiSettings'][1])==n
for n in (21,32):run('one-shot erase stored width and no reboot replay '+str(n),lambda n=n:erase(n))
def lan21():
 m=v.Machine(v.LAN[:21]);m.boot();assert len(m.dev.mutations)==7 and m.dev.sim.lan[4]==b'\1'
 assert all(k=='HeroIpmiState' for k,_ in m.nv_writes);valid_journal(m.vars['HeroIpmiState'][1]);m.no_leak()
 before=len(m.dev.packets);n=m.next_boot();n.boot();assert len(n.dev.packets)==before and len(n.vars['HeroIpmiSettings'][1])==21
run('21-byte LAN retains 144-byte journal and no replay',lan21)
def wdt21():
 m=v.Machine(v.cfg(enabled=1,minutes=7,action=3)[:21]);m.boot();m.call('p6_start_os_watchdog');assert m.dev.sim.wdt[0]&0x40
 valid_journal(m.vars['HeroIpmiState'][1]);m.call('p6_stop_os_watchdog');assert not m.dev.sim.wdt[0]&0x40 and len(m.vars['HeroIpmiSettings'][1])==21;m.no_leak()
run('21-byte watchdog same journal/start/stop semantics',wdt21)
def wrong_readback():
 def fault(m,key,payload):
  if key=='HeroIpmiSettings':m.vars[key]=(3,payload+bytes(32-len(payload)));return 'false'
 m=v.Machine(v.cfg(retry=1)[:21],nv_fault=fault);m.boot();assert not m.dev.packets and len(m.nv_writes)==1
run('width changed during consumed-request readback is failure before BMC',wrong_readback)
def wrong_state():
 m=v.Machine(variables={'HeroIpmiSettings':(3,v.cfg()[:21]),'HeroIpmiState':(3,bytes(144))});assert m.call('p6_seed_settings')==v.ERR(33);m.call('p6_apply_settings');no_mutation(m)
run('21 settings do not relax state CRC/layout',wrong_state)
report={'passed':True,'cases':len(rows),'driver_sha256':hashlib.sha256((HERE/'HeroIpmiP6.efi').read_bytes()).hexdigest(),'results':rows,'scope':'Offline exact new P6 x64 machine code, synthetic services only.'}
(HERE/'tests/settings21-pe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
