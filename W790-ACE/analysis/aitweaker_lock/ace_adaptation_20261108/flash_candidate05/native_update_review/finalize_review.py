"""Build an auditable local review index; does not contact hardware or run REA."""
from pathlib import Path
import hashlib
import json

BASE = Path(__file__).resolve().parent
ROOT = next(p for p in BASE.parents if (p / 'tools/pydeps').is_dir())
CASE = BASE.parent
UP = CASE / 'update_path_reference'


def ref(p):
    b = p.read_bytes()
    return {'path': p.relative_to(ROOT).as_posix(), 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}


def read(p):
    return json.loads(p.read_text(encoding='utf8'))


def evidence(relative):
    p = BASE / relative
    d = read(p)
    e = d.get('result', d)['structuredContent']
    return {'response': ref(p), 'evidence_id': e['evidence_id'], 'subject': e['subject'],
            'provider': e['provider'], 'operation': e['operation'], 'parameters': e['parameters']}


def write(p, d):
    p.write_text(json.dumps(d, ensure_ascii=False, indent=2) + '\n', encoding='utf8')


def main():
    sessions = []
    evidences = []
    all_records = []
    for name in ['native01', 'native02', 'native03', 'native04']:
        s = BASE / name
        closes = []
        commands = []
        responses = []
        for p in sorted((s / 'commands').glob('*.json')):
            commands.append(ref(p))
        for p in sorted((s / 'responses').glob('*.json')):
            responses.append(ref(p))
            d = read(p)
            e = d.get('result', {}).get('structuredContent', {})
            if 'evidence_id' in e:
                record = evidence(p.relative_to(BASE).as_posix())
                record['excluded_from_final_findings'] = name == 'native01' and 'CryptoSMM' in e.get('subject', {}).get('name', '')
                evidences.append(record)
                all_records.append({'response': ref(p), 'excluded_from_final_findings': record['excluded_from_final_findings'], 'evidence': e})
            if 'close' in p.name:
                assert not d.get('result', {}).get('isError', False)
                assert e == {'result': None}
                closes.append(ref(p))
        final = read(s / 'close-finally.json')
        assert not final.get('result', final).get('isError', False)
        sessions.append({'name': name, 'process': ref(s / 'process.json'), 'commands': commands,
                         'responses': responses, 'explicit_closes': closes, 'final_close': ref(s / 'close-finally.json'),
                         'runner_exit_code_observed': 0, 'owned_session_closed': True,
                         'seed_file': ref(s / 'seeds.tsv') if (s / 'seeds.tsv').exists() else None})
    # This is a verbatim collection of returned Evidence records, not a provider export.
    write(BASE / 'full_response_evidence_collection.json', {'format': 'local_collection_of_complete_returned_REA_Evidence',
          'not_a_provider_export': True, 'records': all_records})
    ev = lambda p: evidence(p)['evidence_id']
    old = read(UP / 'rea_update_summary.json')
    old_used = [x for x in old['evidence'] if x.get('parameters', {}).get('procedure') in ['0x397c', '0x3b68', '0x3470', '0xc1c', '0xa48']]
    official = ROOT / 'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
    cap = CASE / 'engineering_signature/W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP'
    report = {
      'schema': 'ace1904_native_update_feasibility_v1',
      'status': 'NO_VERIFIED_NORMAL_NATIVE_PATH_FOR_THIS_ENGINEERING_CAP',
      'scope': 'Offline original ACE1904 EZ Flash/provider/native root review after BMC Prepare failure; no BMC connection, hardware execution, firmware write, trust-anchor change, force path or executable media.',
      'actual_candidate': ref(cap), 'official_basis': ref(official),
      'candidate_payload_sha256': '2dd240c1ddb8890500ce028bb7de25d2db8f687117f4c0d2a57ba400ffbe9809',
      'decision': {
        'same_e330_normal_remote_native_acceptance_proved': False,
        'normal_ezflash_host_update_route_exists_in_original_image': True,
        'native_complete_ezflash_rejection_proved_on_live188': False,
        'original_secsmiflash_root_gate_rejects_e330_under_official_selected_root': True,
        'recommended_action': 'Do not advance this exact CAP into an unverified native update as a workaround for the BMC SPI-init failure. A normally accepted image/path is still required. No change to trust anchors or force/patch method is proposed.',
        'no_new_hardware_validation_wrapper': 'The native validation wrapper is not established as side-effect-free; it reaches original SMI and later state-changing helpers. It is not offered as a read-only hardware probe.'},
      'static_observations': [
        {'id': 'ez_ui', 'finding': 'EZ Flash locates GUID4838e034-d740-4156-9c92-5a1aa4e6ab4f, loads a file through EFI file services, invokes interface+0x58 model checking and, after normal confirmation, interface+0x60 update. It reports completion/reset only for a zero return.',
         'evidence': [ev('native01/responses/002-init.json') if (BASE/'native01/responses/002-init.json').exists() else 'ev_68f43eef765300ae3ed69f29a0b6fb586ae43e2efd3274a76dd354b1099144e4',
                      'ev_c8311e0c982ff119230bde1ff2e903e8565fcb35c0e1d050fe846cfccddc7bfb',
                      'ev_886830e50e816ec915e2836eee98f0fa553b765f6f91f94a6e2f98a57e3df29d']},
        {'id': 'ez_provider', 'finding': 'Original B8F provider installer0xeb8 assigns +0x58=0xbe4 model check and +0x60=0xcf0 program entry. 0x7fc loads/starts the original PEFirmwareUpdateDxe from the selected image and locates87d4c966-0b3d-486b-8d53-e5d1c9d82e40. 0xcf0 first invokes +0x18 validation with mode0x10 and only on zero then +0x10 programming.',
         'evidence': [ev('native03/responses/'+n) for n in ['002-install-EZ-interface.json','003-EZ-model-check.json','004-EZ-program-entry.json','005-EZ-init-image.json','006-preprogram-check.json']]},
        {'id': 'native_validation', 'finding': 'PEFirmwareUpdateDxe+0x18 is VA180001d54; it adds mode0x80000000 and calls1800022b4. 180003b48 begins with180003454 integrity checking. In EZ validation mode0x10, 180003454 securely loads the capsule and invokes180000d24, which constructs mode4 request and calls180000a68(0x1f). SMI transport uses the original initialized host interface; this is distinct from the BMC AST SPI probe.',
         'evidence': [ev('native04/responses/'+n) for n in ['002-validation-mode.json','003-update-common.json','004-init-services.json','005-validate-and-flash.json','006-integrity-gate.json','008-smm-request.json','009-secure-load.json','010-smi-trigger.json']]},
        {'id': 'pei_anchor', 'finding': 'The original PEI producer searches its designated boot FV for hash/X509/raw-RSA key files in order and builds GUID4e0f9bd4-e338-4b26-843e-bd3ad9b2837b HOB. In the exact official boot FV the first two candidate files are absent and raw-RSA file3feec852-f14c-4e7f-97fd-4c3a8c5bbecc exists. Its256-byte public key is exactly the official CAP certificate modulus, SHA1184141882c1afa97a82d768ba34bbffe8002bd5724736c6dc643c045b2eea8c.',
         'evidence': [ev('native02/responses/'+n) for n in ['016-key-producer-entry.json','017-key-producer-hob.json','018-key-file-reader.json']],
         'byte_evidence': [ref(BASE/'pei_key_file_selection.json'),ref(BASE/'root_key_extraction.json')]},
        {'id': 'crypto_anchor', 'finding': 'CryptoSMM1f20 reads that HOB;22dc copies root data. 1fec returns the selected root;20d4 compares a raw-RSA candidate modulus to the root and returns EFI_SECURITY_VIOLATION on mismatch. Fresh unseeded CryptoSMM session is authoritative.',
         'evidence': [ev('native02/responses/'+n) for n in ['009-key-authority.json','010-root-get.json','011-root-locate.json','012-root-initialize.json']]},
        {'id': 'secflash_gate', 'finding': 'SecSMIFlash397c first asks the crypto key-authority method about CAP firmware modulus; if not trusted it tries certificate modulus and verifies its chain before firmware signature. Both e330 moduli differ from the original selected resident root. 3b68 is its original authentication wrapper.',
         'evidence': ['ev_721eba8f945268232fda50e84887baa1a317cf207d0a4f5704d6cc9d71217223','ev_418a59d5e4dd4c020f1b70c2f09c4bbebb634b202182fdb58e7d8312116aee81']}
      ],
      'controlled_replay': ref(BASE/'native_root_gate_replay.json'),
      'replay_scope': 'Six cases execute original CryptoSMM/SecSMIFlash bytes with the root state initialized from the exact official PEI selection. Official CAP reaches the first certificate hash boundary; e330 returns EFI_SECURITY_VIOLATION before any hash/signature callback. No signature success is stubbed and no complete update success is claimed.',
      'inferences': [
        'A host-side original EZ Flash route can avoid the separate BMC external-SPI initialization route; that alone does not confer trust or acceptance on e330.',
        'The original resident SecSMIFlash trust path is an obstacle for e330 despite its mathematically valid self-contained signatures and BMC standalone CAP-validation success.',
        'Preserved model strings/boot FV identify a compatible target image but do not authenticate replacement signing keys.'
      ],
      'unknowns_and_limits': [
        'The final SMI0x1f/mode4 dispatch bridge from PEFirmwareUpdateDxe to the resident authentication provider was not followed instruction-by-instruction. No claim is made that every ASUS native path uses SecSMIFlash397c, or that live EZ Flash rejection has been observed.',
        'The live188 resident root/entire boot FV was not read. The root proof is for the exact official1904 image and unchanged candidate boot FV; live version identity alone does not prove every module is identical.',
        'No actual native EZ Flash file selection, file-system visibility, CheckImage, UpdateCapsule, SetImage or flash operation was executed in this review.',
        'Existing FmpCapsuleUpdate evidence proves image selection and SetImage dispatch, not an independent path accepting this CAP. No alternative normal accepted UpdateCapsule path has been established.',
        'The BMC Prepare WEL timeout is a separate reported hardware-path failure before CAP upload; it says nothing about native CAP acceptance.',
        'No Boot Guard fuse, authenticated IBB coverage, whole-chip backup or recovery guarantee is established by this review.'
      ],
      'analysis_hygiene': {
        'provider': 'REA6.8 with Ghidra12.1.4; local stdio runner; full Evidence preserved',
        'all_four_owned_runner_sessions_closed': True,
        'cross_seed_scout': 'native01 CryptoSMM initially inherited EZFlash seeds. Those records are retained but excluded; clean unseeded native02 CryptoSMM reanalysis supplies all final crypto findings.',
        'indirect_functions': 'Default analysis did not resolve two indirect entries. Original dispatch bytes justified scoped exact seed declarations in native03/provider and native04/PEFirmwareUpdateDxe. No binary was modified.',
        'export_error': 'native04/011 export was rejected for unsupported output_path before any write; explicit close then succeeded. Corrected013 export after close contains zero records and is not used as analysis evidence. Complete raw responses and the local verbatim Evidence collection retain all results.',
        'source_changes': 'Only this independent native_update_review output directory was written.'},
      'evidence': evidences, 'reused_evidence': old_used, 'sessions': sessions,
      'evidence_collection': ref(BASE/'full_response_evidence_collection.json'),
      'supporting_files': [ref(BASE/n) for n in ['runner_binding.json','ez_protocol_inventory.json','public_anchor_search.json','root_key_extraction.json','pei_key_file_selection.json','replay_native_root_gate.py','native_root_gate_replay.json']],
      'external_context': [ref(UP/'rea_update_summary.json'),ref(UP/'api_auth_review/live_staging_review.json')]
    }
    write(BASE/'native_update_feasibility_review.json',report)
    text = '''ACE1904：同一工程 CAP 的原生更新可行性复核

结论：当前没有证据证明 e330039e… 工程 CAP 能通过正常 EZ Flash / UpdateCapsule 路径。不能据此继续实际原生更新，也不能把 BMC 单独 CAP 验签通过当作原生接受。

正常 EZ Flash 的主机侧入口确实存在：文件读取 → 型号检查 → 原 PEFirmwareUpdateDxe 验证方法 → SMI0x1f/mode4 安全检查 → 成功才进入编程。它与 BMC 外部 SPI 初始化是两条路径。但最后的 SMI 派发桥尚未逐函数追完，因此本报告没有声称已完整证明实机 EZ Flash 必然拒绝，也没有声称完成过原生试刷。

已经证明的具体障碍：官方1904的PEI从启动固件卷取出的RSA根公钥与官方CAP证书公钥一致。CryptoSMM读取此根；SecSMIFlash先验证公钥来源再验签。e330换掉的两把公钥都不匹配。6项原字节受控回放全部通过：官方CAP到达证书hash边界，e330在此前返回EFI_SECURITY_VIOLATION。这是离线原代码/官方根状态回放，不是读取实机根，也不是完整刷写模拟。

保留边界：未实测原生文件可见性、UpdateCapsule或FMP接受性；未验证整个实机驻留映像；未读取Boot Guard硬件熔丝。原生“validation”包装器涉及SMI和后续状态操作，没有证明可作无副作用硬件探针，不建议另造介质试探。

最小后续条件仍是获得可由原有可信链正常接受的映像/更新路径，或解决已支持BMC路径的硬件连接/初始化问题；本报告不提出改信任根、强制刷写或绕过验证。BMC Prepare WEL超时与CAP是否被原生接受不能混为一谈。

4个REA运行会话均已关闭，完整原始Evidence、命令、失败/纠正记录和局限见native_update_feasibility_review.json。native04导出因参数错误被拒，关闭后的纠正导出为空；所有完整函数Evidence仍在原响应和明确标识的本地收集文件中，不将空导出冒充分析结果。
'''
    (BASE/'README-原生更新可行性.txt').write_text(text,encoding='utf8')
    write(BASE/'review_index.json',{'status':report['status'],'files':[ref(BASE/n) for n in ['native_update_feasibility_review.json','README-原生更新可行性.txt','native_root_gate_replay.json','full_response_evidence_collection.json','finalize_review.py']]})
    print(json.dumps({'review':ref(BASE/'native_update_feasibility_review.json'),'index':ref(BASE/'review_index.json'),'replay_cases':6,'sessions_closed':4,'evidence_records':len(evidences)},ensure_ascii=False))


if __name__ == '__main__':
    main()
