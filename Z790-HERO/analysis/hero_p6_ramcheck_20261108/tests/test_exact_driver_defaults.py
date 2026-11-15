"""Execute only safe-default lifecycles of the exact frozen P6 PE offline."""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys,zlib
BASE=Path(__file__).resolve().parents[1];ROOT=BASE.parents[1]
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('p6_frozen_runtime',ROOT/'analysis/hero_ipmi_p6_20261104/verify_runtime.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
expected='71dd9b0956f3e3f1dab3893b2106f01aba0745ba6d5ecf7b172a82f8914bfba0'
assert hashlib.sha256((ROOT/'analysis/hero_ipmi_p6_20261104/HeroIpmiP6.efi').read_bytes()).hexdigest()==expected
default=v.cfg();j=bytearray(144);struct.pack_into('<IIIIII',j,0,0x36504948,1,144,0,0,0);j[24:56]=default;j[56:88]=default;struct.pack_into('<I',j,12,zlib.crc32(j))
rows=[]
for have_settings in (False,True):
 for have_state in (False,True):
  variables={}
  if have_settings:variables['HeroIpmiSettings']=(3,default)
  if have_state:variables['HeroIpmiState']=(3,bytes(j))
  m=v.Machine(variables=variables)
  assert m.call('efi_main',v.IMAGE,m.st)==0 and m.api
  for callback in ('on_setup','on_ready','on_before','on_after','on_shell'):
   m.call(callback,0,0)
  assert not m.dev.packets and not m.dev.mutations and not m.pci_writes
  assert len(m.nv_writes)==(0 if have_settings else 1)
  if not have_settings:assert m.nv_writes==[('HeroIpmiSettings',default.hex())]
  assert m.vars['HeroIpmiSettings']==(3,default)
  assert ('HeroIpmiState' in m.vars)==have_state
  if have_state:assert m.vars['HeroIpmiState']==variables['HeroIpmiState']
  assert m.call('unload',v.IMAGE)==v.ERR(15)
  rows.append({'existing_settings':have_settings,'existing_state':have_state,'nv_writes':len(m.nv_writes),'bmc_requests':len(m.dev.packets),'driver_unload_refused':True})
report={'passed':True,'cases':4,'driver_sha256':expected,'rows':rows,'scope':'Actual frozen P6 entry and default-only Setup/Ready/Before/After/Shell callbacks. Native HII/timer querying is reserved for real HERO test; no hardware was connected.'}
(BASE/'tests/exact-driver-defaults.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
