"""Finalize the scoped SMI bridge extension without altering the stage report."""
from pathlib import Path
import hashlib
import json

OUT = Path(__file__).resolve().parent
BASE = OUT.parent
ROOT = next(p for p in BASE.parents if (p / 'tools/pydeps').is_dir())


def ref(p):
    b = p.read_bytes()
    return {'path': p.relative_to(ROOT).as_posix(), 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}


def load(p):
    return json.loads(p.read_text(encoding='utf8'))


def write(p, d):
    p.write_text(json.dumps(d, ensure_ascii=False, indent=2)+'\n', encoding='utf8')


def ev(relative):
    p = BASE/relative
    e = load(p)['result']['structuredContent']
    return {'response':ref(p), 'evidence_id':e['evidence_id'], 'provider':e['provider'],
            'subject':e['subject'], 'parameters':e['parameters']}


def main():
    peer = BASE/'smi_bridge/original_byte_bridge.json'
    assert peer.exists(), 'Independent exact-byte bridge must be finalized first'
    peer_result = load(peer)
    sessions=[]
    for name in ['native05','native06']:
        s=BASE/name
        close=next((s/'responses').glob('*close.json'))
        assert load(close)['result']['structuredContent']=={'result':None}
        assert (s/'close-finally.json').exists()
        sessions.append({'name':name,'process':ref(s/'process.json'),'runner_exit_code_observed':0,
                         'explicit_close':ref(close),'final_close':ref(s/'close-finally.json'),
                         'commands':[ref(p) for p in sorted((s/'commands').glob('*.json'))],
                         'responses':[ref(p) for p in sorted((s/'responses').glob('*.json'))],
                         'provider_bundle':ref(s/('bridge_evidence.json' if name=='native05' else 'install_evidence.json'))})
    evidence=[ev(n) for n in ['native05/responses/003-sw-dispatch.json','native05/responses/004-request-result.json',
                              'native05/responses/005-request-mode.json','native06/responses/002-install-correct-entry.json']]
    report={
      'schema':'ace1904_native_update_smi_bridge_v1',
      'status':'OFFICIAL_1904_NORMAL_EZFLASH_TRUST_CHAIN_CLOSED_LIVE_CUSTOM_ROOT_UNREAD',
      'scope':'Complete only the already identified PEFirmwareUpdateDxe SMI0x1f/mode4 bridge. Offline original bytes/REA only; no hardware connection or execution, media creation, firmware/trust modification.',
      'supplements_without_modifying':ref(BASE/'native_update_feasibility_review.json'),
      'resolves_stage_unknown':'The final SMI0x1f/mode4 dispatcher-to-resident-authentication gap is now closed for the exact original official1904 modules.',
      'same_engineering_cap_sha256':'e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08',
      'official_cap_sha256':'03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29',
      'verdict':{
         'official_1904_normal_ezflash_accepts_this_cap':False,
         'basis':'The original normal EZFlash route reaches the same resident SecSMIFlash/CryptoSMM root gate. The bounded original-code replay rejects both e330 moduli against the exact root selected by the official PEI image. EFI_SECURITY_VIOLATION is not swallowed by the mode4 request wrapper.',
         'live_shuang_1904_acceptance':'NOT_DETERMINED: live complete security modules/root not read; no live native acceptance/rejection observation.',
         'verified_normal_remote_alternative_for_same_e330':False,
         'normal_ui_check_only_preflight_available':False,
         'recommendation':'Do not cross the normal update confirmation merely to inspect signature acceptance. That confirmation authorizes a path that can proceed directly to programming if accepted. No trust change or force path is proposed.'},
      'chain':[
        {'step':1,'module':'EzFlash','rva':'0x17f8','observation':'File/parser/model interface+0x58 runs before the ordinary Do you want to update BIOS confirmation; accepted confirmation calls interface+0x60. This pre-confirmation result is not a complete signature verdict.',
         'evidence':ev('native01/responses/003-ez-update-flow.json')},
        {'step':2,'module':'B8F91F70 provider','rva':'0xcf0','observation':'Interface+0x60 invokes original PEFirmwareUpdateDxe protocol+0x18 with mode0x10. Only a zero result leads, without another user confirmation, to protocol+0x10 programming.',
         'evidence':ev('native03/responses/004-EZ-program-entry.json')},
        {'step':3,'module':'PEFirmwareUpdateDxe','addresses':['0x180001d54','0x1800022b4','0x180003b48','0x180003454','0x180000d24','0x180000a68','0x180004b40'],
         'observation':'Validation adds0x80000000. d24 constructs request byte0=4, DWORD+1=7, length+0x15=0x4001000 and calls a68(0x1f). Original4b40 performs OUT to the initialized host SMI port. d24 accepts only result byte+0x1d=0.',
         'evidence':[ev('native04/responses/'+n) for n in ['002-validation-mode.json','006-integrity-gate.json','008-smm-request.json','010-smi-trigger.json']],
         'original_transport_instructions':ref(OUT/'exact_bridge_bytes.json')},
        {'step':4,'module':'SecSMIFlash','addresses':['0x29f0','0x2d77','0x2db2','0x2db7','0x2ddf'],
         'observation':'Original install function starts29f0, locates dispatch protocol18a3c6dc-5eea-48c8-a1c1-b53389f98999, and registers handler28d4 for contexts0x1d,0x1e,0x1f. Conclusion binds original instructions; default decompiler marks later blocks unreachable due unresolved indirect protocol outputs, a documented provider limitation.',
         'evidence':evidence[3], 'independent_bytes':ref(peer)},
        {'step':5,'module':'SecSMIFlash','rva':'0x28d4','observation':'Reads triggering CPU save state/request pointer. SW input0x1f dispatches to1df8. Other inputs1d/1e select other handlers.', 'evidence':evidence[0]},
        {'step':6,'module':'SecSMIFlash','rva':'0x1df8','observation':'Validates request memory, copies0x1d bytes, calls1b9c, writes byte+0x1d=0 on success or1 on failure. Failure returns generic EFI_DEVICE_ERROR to SMI caller.', 'evidence':evidence[1]},
        {'step':7,'module':'SecSMIFlash','rva':'0x1b9c','observation':'Request flags7 use policy byte91d1=7, allowing mode4. Mode4 executes3b68 authentication, then only on success performs ROM-layout validation22ec. Authentication EFI_SECURITY_VIOLATION(26) propagates. The special EFI25 branch does not convert EFI26 into success.', 'evidence':evidence[2]},
        {'step':8,'module':'SecSMIFlash/CryptoSMM','addresses':['SecSMIFlash0x3b68','SecSMIFlash0x397c','CryptoSMM0x20d4','CryptoSMM0x1fec'],
         'observation':'CAP key-authority decisions use the PEI/HOB resident root before signature verification. Exact official-root replay rejects e330 before any hash/signature callback.',
         'replay':ref(BASE/'native_root_gate_replay.json'),
         'prior_evidence_ids':['ev_418a59d5e4dd4c020f1b70c2f09c4bbebb634b202182fdb58e7d8312116aee81','ev_721eba8f945268232fda50e84887baa1a317cf207d0a4f5704d6cc9d71217223','ev_b8116dbbf37850f207c4c3819fcc907f96530bfd7df612e849d84082fa08d01f']},
        {'step':9,'module':'Failure return','observation':'Gate EFI26 ->1b9c failure ->1df8 result byte1 ->PEFW d24 false ->3454 native status0x80001002 / Security verification failed ->nonzero validation return ->B8F does not call protocol+0x10. The native UI does not expose a separate validated-success stop before programming.'}
      ],
      'limits':[
        'This proves the exact official1904 normal route, not an exhaustive theorem over every firmware recovery path.',
        'Current target is reported as SHUANG-customized1904. Live resident security modules/root were not fully read; no runtime root identity or live native acceptance is asserted.',
        'The original UI file/model stage is not complete signature validation. Full signature validation occurs after update confirmation, with immediate programming on accepted success and possible state side effects inside validation.',
        'No physical flash was attempted through this route. BMC Prepare failure and BMC standalone CAP-validation success remain separate facts.',
        'No Boot Guard fuse/IBB conclusion or recovery guarantee follows from this bridge.'
      ],
      'analysis_hygiene':{
        'stage_report_unchanged':True,'new_REA_sessions_closed':True,'all_owned_sessions_closed_total':6,
        'wrong_seed_record_excluded':ref(BASE/'native05/responses/002-install.json'),
        'wrong_seed_explanation':'Initial2a00 seed pointed inside29f0 prologue and yielded unaff_RBP. Kept for audit, excluded from registration proof. Fresh unseeded native06 analyzes correct29f0; original byte proof independently confirms loop.',
        'decompiler_limit':'Correct-entry Ghidra pseudocode marks registered blocks unreachable. Full original instruction body and independent protocol-call dataflow, not this pruning, establish the registration path.',
        'no_repeat_core_regressions':True},
      'independent_original_byte_review':ref(peer),'exact_original_bytes':ref(OUT/'exact_bridge_bytes.json'),
      'new_REA_evidence':evidence,'sessions':sessions,
      'test_scope':'Reuse six completed original-root-gate cases. New work is four scoped function dossiers plus corrected-entry dossier and independent exact-byte chain, not a new full firmware emulation.'}
    write(OUT/'native_update_bridge_review.json',report)
    text='''原生更新桥接复核已完成（补充阶段报告，不覆盖旧证据）

官方1904正常链：EZ Flash确认更新 → 原PEFirmwareUpdateDxe验证 → SW SMI0x1f/mode4 → SecSMIFlash28d4 →1df8→1b9c→3b68→397c→CryptoSMM根公钥检查。

同e330工程CAP在官方1904原有可信链下会被拒绝：两把公钥不匹配官方PEI选中的驻留根，原字节回放返回EFI_SECURITY_VIOLATION；mode4没有吞掉这个错误，最终传回原生“Security verification failed”，不进入正常编程方法。

现场SHUANG定制1904的完整安全模块与根尚未读取，因此不宣称已观察到实机原生拒绝，也不把官方结论冒充live根测量。当前没有经证实可接收同e330的正常远程替代路线。

普通界面的文件/型号检查在“是否更新BIOS”确认前，完整验签在确认后；验证成功立即编程，没有独立验签成功后的第二个停点。因此不能把跨过该确认用于只读验签预检。

新增两个REA会话已关闭，全部六个自有会话关闭。错误的2a00函数种子与Ghidra对正确入口后段的不可达剪枝均记录为分析局限；注册关系由准确29f0完整原字节/协议数据流独立证明。没有改固件、改可信根、制作新介质或触碰硬件。
'''
    (OUT/'README-桥接定稿.txt').write_text(text,encoding='utf8')
    write(OUT/'review_index.json',{'status':report['status'],'files':[ref(OUT/n) for n in ['native_update_bridge_review.json','README-桥接定稿.txt','exact_bridge_bytes.json','finalize_bridge.py']],'prior_stage_index':ref(BASE/'review_index.json'),'independent_bridge':ref(peer)})
    print(json.dumps({'review':ref(OUT/'native_update_bridge_review.json'),'index':ref(OUT/'review_index.json'),'sessions_closed':6},ensure_ascii=False))


if __name__=='__main__': main()
