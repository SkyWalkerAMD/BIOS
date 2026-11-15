"""Freeze the reviewed browser baseline; no device operations or image edits."""
from pathlib import Path
import argparse,hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent;ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
EFI='2092c11abfc1cc9271357277aaac030424f8dd99c342ae1612f4c0cd3d82e169'
ISO='1841d9a227f11ca7cce4270b75a32213a37e4b772f9040f293133554516db5f8'
M=HERE/'candidate_manifest.json';R=HERE/'candidate_review.json'
def row(p):return{'path':str(p.relative_to(D04)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':sha(p)}
def verify():
 m=json.loads(M.read_text());assert m['efi_sha256']==EFI and m['iso_sha256']==ISO
 for x in m['artifacts']:
  p=D04/x['path'];assert p.stat().st_size==x['bytes']and sha(p)==x['sha256'],str(p)
 print(json.dumps({'status':'PASS_FROZEN_BROWSER_BASELINE06','bindings':len(m['artifacts']),'manifest_sha256':sha(M),'review_sha256':sha(R),'efi_sha256':EFI,'iso_sha256':ISO}))
def freeze():
 assert not M.exists()and not R.exists()
 build=json.loads((HERE/'build/build.json').read_text());assert build['efi_sha256']==EFI and sha(HERE/'build/SageNative13BrowserBaseline06.efi')==EFI
 for s in build['sources']:assert sha(HERE/s['path'])==s['sha256']
 derivation=json.loads((HERE/'source_derivation.json').read_text())
 for x in derivation['inputs']:assert sha(Path(x['source']))==x['source_sha256']
 tests=json.loads((HERE/'browser_byte_test_result.json').read_text());assert tests['efi_sha256']==EFI and tests['cases']==89 and all(x['status']=='PASS'for x in tests['results'])
 delivery=D04/'browser_baseline06_delivery';package=delivery/'packages/2092c11abfc1cc92/package.json';pkg=json.loads(package.read_text());assert pkg['efi_sha256']==EFI and pkg['iso_sha256']==ISO
 runs=list((delivery/'ovmf').glob('*/result.json'));smoke=next(p for p in runs if json.loads(p.read_text()).get('efi_sha256')==EFI);sv=json.loads(smoke.read_text());assert sv['status']=='PASS_EXACT_ISO_OVMF_REFUSAL_AND_QR_TRANSPORT'and sv['qemu_exit_code']==0 and sv['input_images_unchanged']
 ind=D04/'readonly_browser_baseline06_independent_review/whole_app_edges_2092c11abfc1cc92/result.json';assert sha(ind)=='b4ef96b0fddb677e5e4379beb06e04070b93dcf83acf9be2cbed6ec72f4c3ae4'
 report={
 'status':'FROZEN_LOCAL_BROWSER_BASELINE_CANDIDATE_PENDING_TARGET_RESULT',
 'target':'ASUS Pro WS W790E-SAGE SE BIOS 1904 only',
 'efi_sha256':EFI,'efi_bytes':69120,'iso_sha256':ISO,'iso_bytes':16842752,
 'hardware_operations_by_author':False,'native_browser_hardware_pass':False,'password_or_guard_acceptance':False,'firmware_release_ready':False,
 'purpose':'Isolate original ASUS SendForm/form construction/input from the installed native guard and password provider after the RAM_TEST05 M black screen. No result from this baseline alone accepts password protection.',
 'controller':{'B':'One original FormBrowser2 SendForm invocation at most; original interface identity and exact 991-byte frozen P13 independent HII package, same formset and Form1. ActionRequest begins at NONE.','Q':'Immutable complete QR/text snapshot; exact BASELINE06 prefix/footer.','residency':'All paths remain resident until BMC power off, including partial event/protocol/HII publication. No return/unload/remove-published-resource path.','ending':'Both BeforeExitBootServices and ExitBootServices notifications only set an owned flag. Own code CPU-holds before any subsequent firmware service. TPL must equal APPLICATION before selected lifecycle transitions and immediately after native SendForm.'},
 'side_effect_boundary':{'implemented':'Read-only module/stack/map/pagewalk/variable observations; ordinary own-RAM logging, watchdog disable, events, ConfigAccess install and NewPackageList; console/GOP log display.','not_linked':'No transaction installer, native guard, P13 provider, password core, HMAC/PBKDF2, generic setter or variable-write callable type.','not_called':'No direct SetVariable, disk/filesystem/network/flash operation, original module/PTE/CR0/CR3/CR4 write, native image-size change, RuntimeServices replacement, LoadImage or StartImage.','not_claimed':'Original ASUS SendForm and its firmware internals may have side effects. Observing two OC stores cannot prove every OEM variable unchanged.'},
 'identity_and_observation':{'before':'Exact SMBIOS; unique original AMITSE/Setup LoadedImages, original complete .text, pinned PE headers and twelve sites; Core/Bds identity plus exact captured launch return 2D7D or 960C; original FormBrowser2/Setup HII; split provider absence. The launch stack does not prove browser absence.','private':'Only zero-length NULL-buffer size queries of AiTweakerPassword1904. Every required query must return EFI_NOT_FOUND; existing/error state is preserved and refuses. No record content or digest is read.','stores':'Complete 26681-byte OCMR and 1392-byte SocketMemoryConfig with attributes are retained in own RAM, compared before/after, never repaired by a write.','after':'Recheck original .text, PE-header snapshots and twelve sites; this is not an assertion that all runtime image data remained identical.','metadata':'Fixed native globals and text/GOP mode metadata are read before/after; no unknown object traversal or explicit display-mode setter. 83468 is read as qword, matching original AMITSE E1E2 qword store.'},
 'callbacks':{'implementation':'All three ConfigAccess methods only record kind/action/question-id/type/status into 64 bounded own-RAM slots and return EFI_UNSUPPORTED, or EFI_ACCESS_DENIED after EBS. No firmware, display or TPL call; no request/Value dereference and no output-pointer write.','limitation':'FORM_OPEN, FORM_CLOSE, RETRIEVE and other lifecycle requests are rejected too. That behavior can itself influence this OEM browser; a failed baseline must not automatically be attributed to the guard.','overflow':'Overflow is explicit and prevents accepted-return status; no secret material is logged.'},
 'validation':{'actual_pe_browser_models':{'cases':89,'result':row(HERE/'browser_byte_test_result.json'),'scope':'Actual unchanged full PE browser/controller boundary functions; native browser, firmware service endpoints, original identity/map predicates and pure logging are explicit models.'},'independent_full_entry_callbacks':{'cases':31,'result':row(ind),'scope':'Independent actual full entry/ending and unchanged rejected inventory; callback input/output addresses intentionally unmapped; only own RAM records changed.'},'transport_models':{'cases':105,'result':row(delivery/'transport_boundary_result.json'),'scope':'Separate transport carrier and service/ending models; real QR encoder. Not whole-app EBS proof.'},'exact_iso_ovmf':{'result':row(smoke),'scope':'Production identity refuses OVMF; two distinct complete 618-byte QR snapshots, B/M ignored on refused platform, text/QR/Esc transitions, QEMU reaped, package unchanged. No ASUS native form success inferred.'}},
 'source_provenance':'Read-only primitives copied from frozen TX05; exact derivations and input hashes in source_derivation.json. Only a SHA256/zero/equality subset was retained from the crypto implementation. No frozen TX05/P13 source or artifact was edited.',
 'remaining':'Independent final review and explicit hardware run must precede any target-result claim. Persistent Security menu/direct Del/F2 integration, password protection and flash trust/recovery remain separate.'}
 R.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 (HERE/'README.md').write_text('''浏览器基线06用于隔离原厂 ASUS SendForm 与拦截逻辑。当前应用 `2092c11a…`、ISO `1841d9a2…` 只适用于 SAGE SE 1904；不是密码锁或可刷写固件。

按 B 最多调用一次原厂浏览器，显示冻结 P13 的同一份独立 HII 表单。表单里的设置、清除、验证动作全部拒绝，不执行密码逻辑。按 ESC 返回后，Q 可回收完整二维码，T 可看文本。工具始终驻留，最后由 BMC 关机。

应用不安装拦截点、不启动 provider、不直接写变量、磁盘或闪存。它会发布临时协议/HII、注册事件并调用原厂浏览器；这些标准启动服务及原厂内部行为不是“系统零副作用”。私有密码变量仅查询是否存在；OC/MEM 只读比较，不回写。FORM_OPEN 等生命周期回调也拒绝，因此基线失败仍需区分原厂兼容问题和此回调策略。

本地验证包括实际完整 PE 的 89 项边界模型、独立入口/回调 31 项、传输 105 项及精确 ISO 的 OVMF 拒绝/二维码测试。OVMF 不包含 ASUS 原生页面构建链；这些结果不代表真实原厂表单、密码或拦截成功。尚无本候选的实机通过结论。
''',encoding='utf8')
 own=[p for p in HERE.rglob('*')if p.is_file()and p not in [M]and not any(x in ['zig-local','zig-global','tmp','__pycache__']for x in p.parts)]
 external=[package,*package.parent.glob('*'),*smoke.parent.rglob('*'),delivery/'transport_boundary_result.json',ind,D04/'provider13/build/management.pack',D04/'provider13/source/management_package.h',D04/'ram_transaction05/ram_candidate_manifest.json']
 external.extend(Path(x['source'])for x in derivation['inputs'])
 rows={str(p.resolve()):row(p.resolve())for p in own+external if p.is_file()}
 M.write_text(json.dumps({'status':report['status'],'path_base':'installer_design04','efi_sha256':EFI,'iso_sha256':ISO,'artifacts':sorted(rows.values(),key=lambda x:x['path'])},ensure_ascii=False,indent=2)+'\n')
 verify()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--verify-only',action='store_true');a=p.parse_args();verify()if a.verify_only else freeze()
