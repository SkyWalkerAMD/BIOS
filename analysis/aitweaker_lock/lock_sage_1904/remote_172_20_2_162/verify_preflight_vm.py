from pathlib import Path
import importlib.util,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];P3=ROOT/'analysis/aitweaker_lock/probe_p3_kvm'
sys.path.insert(0,str(P3));spec=importlib.util.spec_from_file_location('p3_vm',P3/'verify_vm.py');vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm)
vm.OUT=HERE/'preflight';vm.ISO=vm.OUT/'AiTweaker-SAGE-P4-Preflight.iso'
r=vm.run('usb',1280,800)
if r['passed']:
 data=(vm.OUT/r['folder']/'RESTORED-LOG.TXT').read_bytes()
 assert b'P4_PREFLIGHT_BEGIN\r\n' in data and b'P4_WRITES=NONE\r\n' in data and b'Production.SMBIOS.board_match=0x0000000000000000\r\n' in data
 assert b'Variant=W790E_SAGE_SE_1904_READONLY\r\n' in data
 r['p4_log_and_non_target_guard_verified']=True
(vm.OUT/'vm_validation.json').write_text(json.dumps(r,indent=2),encoding='utf8')
raise SystemExit(0 if r['passed'] else 1)
