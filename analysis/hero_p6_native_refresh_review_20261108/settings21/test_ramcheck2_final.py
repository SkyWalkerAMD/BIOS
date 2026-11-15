"""Independent final S21 loader PE cases; no hardware or frozen-file writes."""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
BASE=ROOT/'analysis/hero_p6_ramcheck2_20261108'
expected='3db419dce892c8aea0add0c3bbfdb40707e61cb395551996987bfcd5ac74b563'
assert hashlib.sha256((BASE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest()==expected
assert hashlib.sha256((BASE/'HERO-P6-RAMCHECK-2.iso').read_bytes()).hexdigest()=='b874d2d5d71e738bfd755e2e9200ce48a573d0e77d71f30e70941e272fbf31d0'
assert hashlib.sha256((BASE/'USB/EFI/BOOT/HEROP6.EFI').read_bytes()).hexdigest()=='6a5e2c86f9e49ceefa47d8765cf45c585805f7ac164f07be07df6505100d8ffb'
manifest=json.loads((BASE/'FROZEN-ARTIFACTS.json').read_text(encoding='utf8'))
for name,row in manifest['files'].items():
 blob=(BASE/name).read_bytes()
 assert len(blob)==row['bytes'] and hashlib.sha256(blob).hexdigest()==row['sha256'],name
path=BASE/'tests/test_launcher_pe.py'
scope={'__file__':str(path),'__name__':'fixture_only'}
exec(compile(path.read_text(encoding='utf8').split('\nrows=[]\n',1)[0],str(path),'exec'),scope)
Machine,DEFAULT,journal=(scope[x] for x in ('Machine','DEFAULT','journal'))
rows=[]
def run(name,m,loads=0,token=None):
 text=m.run()
 assert m.calls.count('Load')==loads and m.calls.count('Start')==loads,(name,text[-2000:])
 assert not token or token in text,(name,text[-2000:])
 assert not any(n.startswith('Forbidden') for n in m.calls)
 rows.append(dict(name=name,passed=True,loads=loads,starts=loads))
for n in (21,32):
 for state in (None,journal()):
  m=Machine(DEFAULT[:n],state)
  run(f'existing exact{n} defaults state_present={state is not None}',m,1,'POST_START_ONLY_EXPECTED_NV_CHANGE=0x0000000000000000')
  assert m.settings==DEFAULT[:n] and m.state==state
for n in (20,22,31,33):
 run(f'reject settings width{n}',Machine((DEFAULT+bytes(4))[:n]))
run('missing seeded exactly32 accepted',Machine(),1,'POST_START_ONLY_EXPECTED_NV_CHANGE=0x0000000000000000')
m=Machine();m.seed_width=21
run('missing unexpectedly seeded21 reported not expected',m,1,'POST_START_ONLY_EXPECTED_NV_CHANGE=0x8000000000000021')
m=Machine(DEFAULT[:21])
def race(m,name,count):
 if name=='HeroIpmiSettings' and count==2:m.settings=DEFAULT
m.mutate=race
run('same normalized fields but width21 to32 race rejects before load',m,0,'LOAD_REFUSED_CHANGED_SINCE_ENTRY')
bad=bytearray(DEFAULT[:21]);bad[0]=1
run('existing21 nondefault configuration rejects load',Machine(bytes(bad)))
result=dict(passed=True,cases=len(rows),launcher_sha256=expected,iso_sha256=manifest['files']['HERO-P6-RAMCHECK-2.iso']['sha256'],core_sha256=scope['EXPECTED'],frozen_manifest_files_verified=len(manifest['files']),results=rows,scope='Actual frozen launcher PE, mocked UEFI services; no hardware, no P6-core invocation. Exact P6 core and AMITSE save machine-code evidence is in native-save-compatibility.json.')
(OUT/'ramcheck2-final-independent.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps(result,indent=2))
