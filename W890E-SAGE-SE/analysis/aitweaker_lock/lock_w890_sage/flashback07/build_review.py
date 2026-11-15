"""Bind official documentation, original bytes and bounded REA filename evidence."""
from pathlib import Path
import hashlib,json,re,struct,zipfile
from datetime import datetime,timezone
D=Path(__file__).resolve().parent;ROOT=D.parents[3];TARGET=D.parent
def sha(b):return hashlib.sha256(b).hexdigest()
def rec(p):
    b=p.read_bytes();return {'path':p.relative_to(ROOT).as_posix(),'bytes':len(b),'sha256':sha(b)}
def dump(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
snapshots={x['url']:x for x in json.loads((D/'source_retrieval.json').read_text(encoding='utf-8'))['retrievals']}
for s in snapshots.values():
    assert s['status']==200
    assert rec(ROOT/s['path'])['sha256']==s['sha256']
manuals=json.loads((D/'manual_retrieval.json').read_text())
for m in manuals:assert m['status']==200 and rec(D/m['path'])['sha256']==m['sha256']
for name in ['model-bios.html','model-manual.html']:
    s=(D/'sources'/name).read_text(encoding='utf-8')
    pool=json.loads(re.search(r'<script[^>]+id="__NUXT_DATA__"[^>]*>(.*?)</script>',s,re.S).group(1));rows=[]
    for x in pool:
        if isinstance(x,dict) and all(k in x for k in ['Version','Title','Description','DownloadUrl']):
            row={k:pool[x[k]] if isinstance(x[k],int) and 0<=x[k]<len(pool) else x[k] for k in ['Version','Title','Description','DownloadUrl','ReleaseDate','FileSize','sha256'] if k in x}
            if isinstance(row.get('DownloadUrl'),dict):row['DownloadUrl']={k:pool[a] if isinstance(a,int) and 0<=a<len(pool) else a for k,a in row['DownloadUrl'].items()}
            rows.append(row)
    dump(D/name.replace('.html','-items.json'),rows)
    if name=='model-bios.html':bios=next(x for x in rows if x['Version']=='0603')
zpath=ROOT/'Pro-WS-W890E-SAGE-SE-ASUS-0603.zip'
cap=ROOT/'analysis/workstation_20261008/W890_SAGE_0603/Pro-WS-W890E-SAGE-SE-ASUS-0603.CAP'
b=cap.read_bytes();assert rec(zpath)['sha256']==bios['sha256'].lower()
assert rec(cap)['sha256']=='c7b12934cd0904a9cd4cfca53f656931bd5164e3bc30b99b043c2c2cb39a92d1'
with zipfile.ZipFile(zpath) as z:
    assert z.read(cap.name)==b
    assert z.read('BIOSRenamer.exe')==(D/'sources/BIOSRenamer.exe').read_bytes()
machine=json.loads((D/'renamer_machinecode_tests.json').read_text())
assert machine['original_cap_sha256']==sha(b) and machine['passed']==2
assert machine['source_sha256']==sha((D/'test_renamer.py').read_bytes())
assert machine['filename']=='A5709.CAP' and all(x['pass'] for x in machine['tests'])
assert struct.unpack_from('<I',b,16)[0]==0x1000 and len(b)==0x4001000
assert b[int(machine['filename_offset'],16):int(machine['filename_offset'],16)+10]==b'A5709.CAP\0'
evidence=[]
for n in range(1,8):
    p=D/f'rea04/response-{n:03}.json';r=json.loads(p.read_text());assert not r.get('isError')
    e=r['structuredContent'];evidence.append({'file':p.relative_to(D).as_posix(),'operation':e.get('operation'),'evidence_id':e.get('evidence_id')})
assert (D/'rea04/final-close.json').exists() and (D/'rea04/evidence.json').exists()
old=json.loads((TARGET/'release_review/original_static_review.json').read_text())
assert old['original']['sha256']==sha(b) and old['signature']['firmware']['valid'] and old['negative_controls']['changed_dxe_rejected']
sources={
 'model_manual_english':{'url':manuals[1]['url'],'source':rec(D/manuals[1]['path']),'reviewed_pages':[13,43,69,74]},
 'model_manual_chinese':{'url':manuals[0]['url'],'source':rec(D/manuals[0]['path']),'reviewed_pages':[16,72]},
 'model_bios_0603':{'url':next(u for u in snapshots if 'helpdesk_bios' in u),'source':rec(D/'sources/model-bios.html'),'release_date':bios['ReleaseDate'],'official_zip_sha256':bios['sha256'].lower(),'zip_url':'https://dlcdnets.asus.com'+bios['DownloadUrl']['Global']},
 'flashback_general_faq':{'url':'https://www.asus.com/support/faq/1038568/','source':rec(D/'sources/flashback-faq.html'),'scope':'Generic ASUS instructions, supplemented by exact-model manual; not a W890 signature policy declaration'},
 'model_specs_online':{'url':'https://www.asus.com/motherboards-components/motherboards/workstation/pro-ws-w890e-sage-se/techspec/','scope':'Read via browser tool; confirms model and rear FlashBack button, no local HTML snapshot claimed'}
}
review={
 'schema':'w890-flashback-deployment-review-v1',
 'created_utc':datetime.now(timezone.utc).isoformat(),
 'target':'ASUS Pro WS W890E-SAGE SE 0603',
 'status':'OFFICIAL_FLASHBACK_ROUTE_CONFIRMED_MODIFIED_IMAGE_ACCEPTANCE_NOT_ESTABLISHED',
 'decision_change':{'selected_transport':'USB BIOS FlashBack','BMC_update_acceptance_required':False,'reason':'User explicitly accepted FlashBack-only BIOS updates, as relayed by parent; hardware boot policy and restoration evidence remain separate requirements.'},
 'actions':{'original_files_modified':False,'native_BIOSRenamer_launched':False,'hardware_connected':False,'BMC_accessed':False,'firmware_uploaded':False,'firmware_flashed':False,'CAP_candidate_created':False,'keys_or_signatures_created':False},
 'original':{'zip':rec(zpath),'cap':rec(cap),'renamer':rec(D/'sources/BIOSRenamer.exe'),'official_zip_digest_matches_local':True,'zip_CAP_matches_extracted_CAP':True,'header_bytes':4096,'payload_bytes':67108864,'total_CAP_bytes':67112960},
 'official_sources':sources,
 'file_contract':{'filename':'A5709.CAP','root_directory':True,'inputs':'Complete vendor CAP file, not the ZIP, standalone ME update BIN, extracted PE, or a header-stripped raw image. This defines the documented transport input, not modified-image approval.','corroboration':['model_manual_english p13 and p69','model_manual_chinese p16 and p72','model_bios_0603 description','original CAP offset 0x3E7FC2D','original BIOSRenamer parser REA and actual instruction replay'],'original_manual_name_confirmed_visually':True},
 'usb_contract':{'documented_format':['FAT16','FAT32'],'partition_scheme':'MBR','capacity_minimum_documented':'1 GB','exact_capacity_minimum_bytes':None,'capacity_wording':'ASUS generic FAQ says 1 GB or more; no exact binary-byte threshold or maximum was established.','geometry_wording':'FAQ says single-sector USB. Do not treat this translation as evidence of a required 512-byte sector size. A single MBR FAT32 partition is the proposed conventional preparation choice, not a newly verified controller requirement.','proposed_preparation':'One MBR FAT32 partition, A5709.CAP at root; exact USB device compatibility still needs physical confirmation.'},
 'physical_contract':{'sources':['model_manual_english p43 and p69','model_manual_chinese p72'],'port':'Looking directly at rear I/O: lower Type-A USB port in the rightmost Ethernet+USB stack, immediately left of the audio-jack stack. It is the lower port of the USB 5/6 pair, under the 10GbE port nearest audio.','button':'Small FlashBack button below the VGA block at left; the button below the audio stack is Clear CMOS and is different.','power':'24-pin motherboard power connected, PSU switched on, system does not need to be powered on.','start':'Hold the FlashBack button about 3 seconds; three LED blinks indicate start.','completion':'Wait for the FlashBack indicator to go out. Do not interpret the start blinks alone as success.','interruption':'Do not remove USB/power, power on, press Clear CMOS, or short CLRTC during the update.','failure_signal':'Manual describes about five seconds of flashing followed by steady light as unsuccessful operation; wrong media/file/name/format are listed possibilities, not a complete signature-error decoder.','onsite_execution':'The documented route needs physical USB insertion and button operation. No equivalent BMC action has been established, and no onsite operator availability is assumed.'},
 'renamer_evidence':{'REA':evidence,'machinecode_report':rec(D/'renamer_machinecode_tests.json'),'parser':'VA 0x401050..0x401222; original x86 bytes; RAM file/allocation API model','observed_result':'A5709.CAP for original CAP and a RAM-only DXE-byte-change case','filename_offset':'0x3E7FC2D','not_proved':['FlashBack file recognition','FlashBack signature policy','flash programming','boot success'],'native_detail':'Parser returns EAX pointing into its heap buffer despite incomplete recovered void return type. It writes a NUL at filename+12 in RAM. Main prints its renamed message before calling _rename at 0x4013DA and does not check that return; printed text is not proof of an on-disk rename.'},
 'signature_boundary':{'mathematical_baseline_source':rec(TARGET/'release_review/original_static_review.json'),'original_signature_self_consistent':True,'changed_signed_DXE_invalidates_original_signature':True,'FlashBack_controller_policy':'UNKNOWN','reason':'Neither exact-model instructions nor the desktop filename utility establishes whether this board FlashBack controller authenticates the capsule, which root it trusts, or which areas it writes. No inference from older W790/X299 boards or BMC code is used.','must_not_claim':['FlashBack bypasses OEM signatures','all modified images are rejected','renaming fixes a signature','BMC acceptance proves FlashBack acceptance']},
 'boot_policy_boundary':{'source':rec(TARGET/'boot_policy07/original_boot_policy.json'),'AMITSE_measured_coverage':'UNKNOWN','fuse_and_runtime_enforcement':'UNKNOWN','flash_programming_does_not_prove_bootability':True},
 'recovery_boundary':{'documented':'Model manual describes repeating FlashBack after interruption and ASUS service if recovery fails. It also documents a separate CrashFree BIOS 3 path.','CrashFree_distinction':'English manual p74: a running recovery path searches USB and enters EZ Flash. Its alternate ASUS.CAP name is not the FlashBack filename; use A5709.CAP for FlashBack.','original_0603_recovery_file_identity':rec(cap),'original_flashback_round_trip_observed':False,'exact_SPI_write_scope_and_preserved_board_data':'UNKNOWN','hardware_restoration_after_bad_DXE':'UNTESTED','backup_is_not_a_verified_restore_path':True},
 'ME_boundary':{'official_0603_release_note_version':'19.10.6.1494','official_0603_note':'The model release note associates 0603 with ME 19.10.6.1494 and states that rolling BIOS back does not roll ME back.','zip_contains_separate_ME_payload':True,'physical_FlashBack_ME_write_scope':'UNKNOWN','reason':'A generic Intel 800-series FAQ also discusses a separate ME step. Do not flatten these different-scope statements into a claim about W890 controller coverage. No ME change is required or performed by this review.'},
 'remaining_evidence_matrix':[
  {'gate':'Correct model/input/name/port instructions','state':'VERIFIED_OFFLINE','evidence':'Official manual, matching official published ZIP digest, original CAP and utility'},
  {'gate':'Complete integrated password-lock behavior','state':'OUTSIDE_THIS_REVIEW_NOT_RELEASED','evidence':'No current lock readiness claim is made here'},
  {'gate':'Physical USB+controller recognizes original 0603 and completes restoration','state':'UNTESTED','evidence_needed':'Actual onsite original-image FlashBack and return to known firmware, preserving machine identity/configuration evidence'},
  {'gate':'Controller accepts intended modified CAP without unsafe packaging assumptions','state':'UNKNOWN','evidence_needed':'Board-specific controller validation path or a carefully bounded physical acceptance test with established recovery'},
  {'gate':'Modified image boots under current platform policy','state':'UNKNOWN','evidence_needed':'Verified affected-region policy evidence plus actual cold/warm boot testing; FlashBack LED completion alone is insufficient'},
  {'gate':'Password UI persistence, every entry and ordinary settings, recovery and defaults','state':'NOT_ESTABLISHED_BY_FILENAME_TESTS','evidence_needed':'Completed integration tests and hardware scenarios bound to final image hash'}
 ],
 'release_ready':False,
 'conclusion':'USB BIOS FlashBack is the correct supported physical transport to target. Exact filename and preparation instructions are established. Modified-image acceptance, bootability and tested restoration remain unproven; this report is not a flashable release.'
}
dump(D/'flashback_review.json',review)
manifest={'status':'FROZEN_FLASHBACK_ROUTE_REVIEW_NOT_A_FLASHABLE_PACKAGE','files':[],'external_bindings':[rec(p) for p in [zpath,cap,TARGET/'release_review/original_static_review.json',TARGET/'boot_policy07/original_boot_policy.json',TARGET/'hsti_review07/snapshot.json']]}
for p in sorted(D.rglob('*')):
    if p.is_file() and p.name!='component_manifest.json' and not any(x in ['tmp','__pycache__'] for x in p.relative_to(D).parts):manifest['files'].append(rec(p))
dump(D/'component_manifest.json',manifest)
for row in manifest['files']+manifest['external_bindings']:assert rec(ROOT/row['path'])==row
print(json.dumps({'review':rec(D/'flashback_review.json'),'manifest':rec(D/'component_manifest.json'),'files':len(manifest['files']),'external_bindings':len(manifest['external_bindings'])},ensure_ascii=False))
