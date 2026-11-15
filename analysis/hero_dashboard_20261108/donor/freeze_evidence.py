from pathlib import Path
import sys,json,hashlib,struct
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
pepath=OUT/'B1DA0ADF-4F77-4070-A88E-BFFE1C60529A.efi'
pe=pefile.PE(str(pepath));image=pe.get_memory_mapped_image()
assert struct.unpack_from('<Q',image,0x73138)[0]==0x3b1dc
assert struct.unpack_from('<Q',image,0x6e1f0)[0]==0x3a0f4
assert image[0x6e1f0+0x1c]==1
emulated=json.loads((OUT/'donor-dmi-machine-code.json').read_text())
livepath=OUT.parent/'dmi-publication-result.json'
live=json.loads(livepath.read_text());packets={p['selector']:bytes.fromhex(p['request_hex']) for p in emulated['actual_case']['packets']}
writes=[r for r in live['records'] if r['type']=='sending' and r.get('netfn')==0x30 and r.get('command')==4]
assert len(writes)==2
assert [bytes.fromhex(r['request_hex'])[0] for r in writes]==[2,0]
checks=[]
for r in writes:
    b=bytes.fromhex(r['request_hex']);sel=b[0];assert b==packets[sel]
    response=next(x for x in live['records'] if x['type']=='response' and x.get('command')==4 and x['request_hex']==r['request_hex'])
    assert response['completion']==0 and bytes.fromhex(response['response_hex'])==bytes([len(b)-1])
    read=next(x for x in live['records'] if x['type']=='response' and x.get('command')==3 and x['request_hex']==bytes([sel,0,0,len(b)-1]).hex())
    assert read['completion']==0 and bytes.fromhex(read['response_hex'])==bytes([len(b)-1])+b[1:]
    checks.append({'selector':sel,'request_bytes':len(b),'request_sha256':hashlib.sha256(b).hexdigest(),
                   'body_bytes':len(b)-1,'body_sha256':hashlib.sha256(b[1:]).hexdigest(),
                   'matches_actual_donor_constructor':True,'live_write_completion':0,'live_readback_equal':True})
api=json.loads((OUT.parent/'responses/005-evaluate.json').read_text())['result']['data']
assert {k:api[k] for k in ('BIOSVersion','BIOSDate','BIOSModel')}=={
    'BIOSVersion':'3107','BIOSDate':'11/28/2025','BIOSModel':'ROG MAXIMUS Z790 HERO'}
oldrea=ROOT/'analysis/hero_remote_bios_r3/rea-publisher/responses/001-open.json'
source=json.loads(oldrea.read_text())['result']['structuredContent']['result']
assert source['sha256']==sha(pepath)
result={'scope':'offline donor analysis and independent verification of parent-owned live artifacts',
  'donor_cap':{'path':'ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP','sha256':sha(ROOT/'ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP')},
  'module':{'guid':'B1DA0ADF-4F77-4070-A88E-BFFE1C60529A','name':'AMITSE','bytes':pepath.stat().st_size,'sha256':sha(pepath),'entry_rva':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)},
  'legacy_callback_evidence':{'hook_table_rva':'0x73030','hook_id':'0xffff0006','callback_pointer_rva':'0x73138',
      'callback_rva':'0x3b1dc','record_table_rva':'0x6e1f0','record_bytes':29,'record0_constructor_rva':'0x3a0f4','record0_enabled':1,
      'preconditions':['LocateProtocol EFI_DXE_IPMI_TRANSPORT success','LocateProtocol EFI_SMBIOS_PROTOCOL success'],
      'record_order':[0,1,2], 'event_phase':'not proven; no claim of ReadyToBoot or automatic invocation in this build'},
  'rea_reuse':{'file':str(oldrea.relative_to(ROOT)),'sha256':sha(oldrea),'target_sha256_matched':True,
      'prior_decompile_file':'analysis/hero_remote_bios_r3/rea-publisher/responses/002-entry.json',
      'prior_decompile_status':'provider_timeout; no pseudocode Evidence claimed','new_provider_started':False},
  'live_comparison':{'file':str(livepath.relative_to(ROOT)),'sha256':sha(livepath),'checks':checks,
      'api_file':'analysis/hero_dashboard_20261108/responses/005-evaluate.json','api_fields':{k:api[k] for k in ('BIOSVersion','BIOSDate','BIOSModel')},
      'ui_file':'analysis/hero_dashboard_20261108/responses/008-login.json','screenshot':'analysis/hero_dashboard_20261108/screens/dashboard-after.png',
      'automatic_boot_sync_proven':False},
  'owned_processes_running':False}
(OUT/'evidence-summary.json').write_text(json.dumps(result,indent=2)+'\n')
files={p.name:{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(OUT.iterdir()) if p.is_file() and p.name!='manifest.json'}
(OUT/'manifest.json').write_text(json.dumps(files,indent=2)+'\n')
print(json.dumps({'checks':checks,'owned_processes_running':False,'files':len(files)},indent=2))
