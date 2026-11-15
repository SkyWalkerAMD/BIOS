"""Freeze bounded independent baseline06 evidence, or verify it read-only."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,re,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;B06=D04/'readonly_browser_baseline06';DEL=D04/'browser_baseline06_delivery'
ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
EFI='2092c11abfc1cc9271357277aaac030424f8dd99c342ae1612f4c0cd3d82e169'
ISO='1841d9a227f11ca7cce4270b75a32213a37e4b772f9040f293133554516db5f8'
bindings={}
def bind(p,expected=None,size=None):
 p=Path(p).resolve();assert p.is_relative_to(ROOT)
 digest=sha(p);assert expected is None or digest==expected,(str(p),digest,expected)
 assert size is None or p.stat().st_size==size
 rel=str(p.relative_to(ROOT)).replace('\\','/');bindings[rel]={'path':rel,'bytes':p.stat().st_size,'sha256':digest};return bindings[rel]
def rows(items,base):
 for r in items:bind(base/r['path'],r['sha256'],r.get('bytes'))
def src_line(path,token):
 p=B06/'source'/path;hits=[i for i,s in enumerate(p.read_text().splitlines(),1)if token in s];assert hits
 return {'path':str(p.relative_to(ROOT)).replace('\\','/'),'line':hits[0],'sha256':sha(p)}
def main():
 manifest=HERE/'independent_manifest.json';out=HERE/'independent_review.json'
 if sys.argv[1:]==['--verify-only']:
  saved=json.loads(manifest.read_text());rows(saved['artifacts'],ROOT);print(json.dumps({'status':'PASS_READONLY_ALL_BINDINGS','artifacts':len(saved['artifacts']),'manifest_sha256':sha(manifest),'review_sha256':sha(out)}));return
 assert not sys.argv[1:] and not out.exists() and not manifest.exists()
 author_manifest=B06/'candidate_manifest.json';bind(author_manifest,'b3a11eb8adc9835f917e777d4f7d137786caaf82ffb4809126e2eb4a120b3cbb')
 author=json.loads(author_manifest.read_text());assert author['efi_sha256']==EFI and author['iso_sha256']==ISO and author['path_base']=='installer_design04'
 rows(author['artifacts'],D04);assert len(author['artifacts'])==98
 author_review=B06/'candidate_review.json';bind(author_review,'63f3d24687d3f98e5ae81b7ad2e4531daa478297384f5b6cf4df0809801db1c7')
 build=B06/'build/build.json';b=json.loads(build.read_text());assert b['efi_sha256']==EFI
 for r in b['sources']:bind(B06/r['path'],r['sha256'])
 for n,h in b['objects'].items():bind(B06/'build'/n,h)
 bind(build);bind(B06/'build/app.map');bind(B06/'build/SageNative13BrowserBaseline06.efi',EFI)
 assert [Path(cmd[-3]).name for cmd in b['commands'][:-1]]==['app.c','browser.c','inventory.c','sha256.c','kvm.c','probe_core.c','qrcodegen.c','entry.S']
 symbols=(B06/'build/app.map').read_text();assert not re.search(r'\s(?:tx_install|tx_remove|provider_main|ap_pbkdf2|ap_hmac)\s',symbols)
 browser=json.loads((B06/'browser_byte_test_result.json').read_text());assert browser['efi_sha256']==EFI and browser['cases']==89 and browser['status'].startswith('PASS_')
 bind(B06/'test_browser_bytes.py',browser['test_sha256']);bind(B06/'browser_byte_test_result.json')
 entry_path=HERE/('whole_app_edges_'+EFI[:16])/'result.json';entry=json.loads(entry_path.read_text());assert entry['efi_sha256']==EFI and entry['cases']==31 and entry['status'].startswith('PASS_')
 for p in entry_path.parent.iterdir():
  if p.is_file():bind(p)
 bind(HERE/'verify_entry_callbacks.py',entry['test_source_sha256']);bind(entry_path,'b4ef96b0fddb677e5e4379beb06e04070b93dcf83acf9be2cbed6ec72f4c3ae4')
 ops=json.loads((HERE/'operations_review.json').read_text());rows(ops['bindings'],ROOT)
 bind(HERE/'operations_review.json','455cf118a1ef02da7ba0b14658beecf50e622b3a7ce413bc996d3e1110747508');bind(HERE/'review_operations.py');bind(HERE/'operations05_to06.diff.txt')
 delivery=json.loads((HERE/'delivery_review.json').read_text());assert delivery['efi_sha256']==EFI and delivery['iso_sha256']==ISO
 rows(delivery['bindings'],ROOT);bind(HERE/'delivery_review.json','51fd3b9cacf4fb8f7f514b72ed023e050c6251a80e7451c1f57117889aee5b39')
 tr=DEL/'transport_boundary_result.json';t=json.loads(tr.read_text());assert t['checks']==105 and t['post_ending_firmware_calls']==0
 bind(tr);bind(B06/'source/transport/kvm.c',t['source_sha256']);bind(DEL/'verify_transport_boundary.py',t['test_source_sha256']);bind(DEL/'transport_boundary_build/TransportBoundary.TESTONLY.efi',t['test_efi_sha256']);bind(DEL/'transport_boundary_build/build.json',t['build_sha256'])
 td=json.loads((DEL/'transport_boundary_build/build.json').read_text())
 for p,h in td['sources'].items():bind(p,h)
 pd=DEL/'packager_derivation.json';der=json.loads(pd.read_text());bind(pd);bind(der['source'],der['source_sha256']);bind(der['packager'],der['packager_sha256'])
 for r in der['transport_test_derivation']:bind(r['source'],r['source_sha256']);bind(r['output'],r['output_sha256'])
 # Check the native metadata width independently instead of inferring it from
 # the variable name or the diagnostic's C type.
 native=ROOT/'analysis/aitweaker_lock/lock_sage_1904/analysis/modules/AMITSE.efi';bind(native,'531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1')
 pe=pefile.PE(str(native));mem=pe.get_memory_mapped_image();cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 inst=next(cs.disasm(mem[0xe1e2:0xe1f0],0xe1e2));assert inst.mnemonic=='mov'and inst.operands[0].size==8 and inst.operands[1].imm==4
 assert inst.address+inst.size+inst.operands[0].mem.disp==0x83468
 stage={'rva':'0xE1E2','bytes':inst.bytes.hex(),'instruction':inst.mnemonic+' '+inst.op_str,'target_rva':'0x83468','write_bytes':8,'value':4,'scope':'The diagnostic records the current raw qword; this does not independently assign lifecycle semantics to its value.'}
 findings=[
  {'finding':'Source/build separation','result':'Eight explicit objects only; read-only inventory, SHA256 subset, own controller/browser, display/QR and entry capture. No transaction, guard, provider, credential implementation, disk/network or original-module writer is linked. Names of protected sites in targets.h are inventory labels, not executable hooks.','source':src_line('inventory.c','int baseline_inventory(void)')},
  {'finding':'Exact bounded admission','result':'Original identity, complete text hashes, header/12-window identities, Core/Bds/launch provenance and original FormBrowser2 identity are required. Launch context is explicitly not proof of browser absence. Snapshot query of credential is size zero and must return NOT_FOUND.','source':src_line('browser.c','int browser_capture(void)')},
  {'finding':'Standard volatile publication and ownership','result':'ConfigAccess is installed on an initially null new handle, followed by the exact frozen 991B package. Every publication attempt is one-shot. Partial successes remain resident; no unload/return/removal/free path can orphan callbacks. This is not zero volatile firmware state change.','source':src_line('browser.c','int browser_publish(void)')},
  {'finding':'Callback denial boundary','result':'All three callbacks only append numeric metadata to 64 private RAM records. Independent actual-byte tests use unmapped request/output pointers, verify only owned log modifications, check ended status and the 65th-call overflow. No service/TPL/display/output-pointer write occurs.','source':src_line('browser.c','ES EA baseline_extract')},
  {'finding':'Single original browser call','result':'Both app attempted and browser invoked flags prohibit retry. Exact published handle/formset/Form1 are used, screen dimensions null and UINTN ActionRequest initially NONE. Returned status/request, original text/headers/sites, private absence and OC/MEM bytes+attrs are checked. Differences are observed, never repaired.','source':src_line('browser.c','int browser_invoke(void)')},
  {'finding':'EBS, TPL and residency','result':'Actual entry registers before/final EBS callbacks, disables watchdog and remains resident on failures. Owned ending flag is checked after service returns. Native SendForm return checks ending then TPL before later variable/display services. Anomalous TPL holds rather than restoring an assumed value. Console/QR internal boundaries are separately reviewed.','source':src_line('app.c','ES EA app_main')},
  {'finding':'Final optical artifact','result':'Raw ElTorito catalog/checksum, only EFI boot entry, both FAT copies, all cluster chains/no orphans and sole BOOTX64.EFI bytes match the reviewed final EFI. Two 618B OVMF QR snapshots were decoded again from raw PNGs with page/full CRC and compared to frames/logs. Eight PNG/PPM pairs match exactly.'},
  {'finding':'Operator tools','result':'Current menu b/q matches strict key tool; no password input or TX05 modes are allowed. Capture preserves attempts, CRC and semantic-pending. Manual screenshot gate does not recognize screen contents. Single standard ForceOff acceptance is not an Off observation or rollback of OEM state.'},
 ]
 result={'status':'PASS_INDEPENDENT_LOCAL_REVIEW_FOR_ONE_BOUNDED_MANUAL_BROWSER_BASELINE_ATTEMPT','utc':datetime.now(timezone.utc).isoformat(),'efi_sha256':EFI,'iso_sha256':ISO,'device_operations_by_reviewer':0,'confirmed_local_blockers':[],'source_and_object_counts':{'sources':len(b['sources']),'objects':len(b['objects']),'author_manifest_artifacts':len(author['artifacts'])},'findings':findings,'metadata_width_evidence':stage,'validation':{'independent_actual_whole_app_entry_callbacks':31,'author_actual_browser_with_explicit_inventory_map_sendform_log_models':89,'separate_transport_carrier_with_service_and_ending_models':105,'exact_iso_ovmf_refusal_checks':6,'independent_raw_png_ppm_pairs':8,'independent_complete_qr_snapshots':2,'new_execution_by_reviewer':'31 actual unchanged whole-app PE cases plus independent raw media/image/CRC verification; author89/root105 were source-reviewed and hash-bound, not rerun.'},'manual_test_prerequisites':['Parent retains sole control of target and maintenance authorization; no direct device action is performed by this audit.','Use only exact EFI2092/ISO1841, collect initial complete baseline06 QR first and require expected original SAGE1904 identity/private absence before the single b attempt.','No password action or saving/resetting from the form; ESC return and capture if responsive. If unresponsive, rely only on the reviewed standard power-off operation and independent Off readback, without diagnosing CPU hold from pixels.'],'limitations':['Actual original ASUS SendForm/form construction/input has not passed this new baseline on hardware yet. The prior TX05 attach passed, but its management M attempt remained black and unaccepted.','Rejecting lifecycle ConfigAccess callbacks can itself alter OEM browser behavior. Success/failure is a narrowing observation, not proof that the TX05 guard caused or did not cause the black screen.','No direct setter is linked, but standard OEM browser internals may write variables, cache or other state. Two observed stores and current private absence do not establish all NVRAM/SPI unchanged.','The original-code check covers immutable text/header snapshots and twelve selected sites; it is not whole mutable-image byte equality.','Hardware maps/GUI are not proven by explicit Unicorn endpoint models or unsupported-board OVMF boot. PE section permission bits do not prove runtime W^X.','No persistent password UI, direct Del/F2/cold entry, flash trust, complete backup/recovery or firmware release acceptance follows.'],'hardware_browser_pass':False,'password_or_guard_acceptance':False,'firmware_release_ready':False,'evidence':{'author_manifest':bind(author_manifest),'author_review':bind(author_review),'entry_callbacks':bind(entry_path),'delivery_review':bind(HERE/'delivery_review.json'),'operations_review':bind(HERE/'operations_review.json')}}
 bind(Path(__file__));out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8');bind(out)
 manifest.write_text(json.dumps({'status':'FROZEN_INDEPENDENT_BASELINE06_LOCAL_REVIEW','path_base':'workspace','efi_sha256':EFI,'iso_sha256':ISO,'artifacts':list(bindings.values())},indent=2)+'\n',encoding='utf8')
 print(json.dumps({'status':result['status'],'artifacts':len(bindings),'review_sha256':sha(out),'manifest_sha256':sha(manifest)}))
if __name__=='__main__':main()
