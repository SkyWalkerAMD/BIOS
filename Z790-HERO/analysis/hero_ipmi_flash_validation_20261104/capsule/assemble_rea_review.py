"""Bind the bounded HERO CAP review to retained REA results and original files."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import capstone


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def evidence(session, filename):
    path = HERE / session / 'responses' / filename
    item = read_json(path)['result']['structuredContent']
    return dict(evidence_id=item['evidence_id'], raw_response=str(path),
                raw_response_sha256=sha(path.read_bytes()),
                subject=item['subject'], operation=item['operation'], parameters=item['parameters'])


def main():
    math_report = read_json(HERE / 'hero_capsule_authentication.json')
    ssl_report = read_json(HERE / 'hero_openssl_authentication.json')
    view = read_json(HERE / 'rootkey_pe_view_manifest.json')
    modules = read_json(HERE / 'hero_auth_modules_compare.json')
    assert all(m['identical'] for m in modules)
    refs = {
        'root_publication': evidence('rea-key-peim', '004-key-publication.json'),
        'root_ffs_read': evidence('rea-key-peim', '005-key-read-helper.json'),
        'capsule_dispatch': evidence('rea-smm', '010-capsule-functions.json'),
        'certificate_and_firmware_verify': evidence('rea-smm', '011-authentication-callees.json'),
        'signed_stream': evidence('rea-smm', '013-signed-stream-builder.json'),
        'smm_init_and_error_propagation': evidence('rea-smm', '019-init-authenticated-flash-entry.json'),
        'crypto_protocol_install': evidence('rea-crypto', '005-initialize.json'),
        'crypto_hob_read_and_getkey': evidence('rea-crypto', '009-key-and-rsa-functions.json'),
        'rsa_callback_bytes': evidence('rea-crypto', '010-rsa-callback-raw-evidence.json'),
    }
    p = HERE / 'rea-crypto/responses/010-rsa-callback-raw-evidence.json'
    raw = bytes.fromhex(read_json(p)['result']['structuredContent']['normalized_result']['bytes_hex'])
    crypto = (HERE / 'HERO-3107-2AD511C7-CryptoSmm.efi').read_bytes()
    assert raw == crypto[0x1D04 - 0xC00:0x1E74 - 0xC00]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    asm = '\n'.join(f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in md.disasm(raw, 0x1D04))
    (HERE / 'crypto_rsa_callback_disassembly.txt').write_text(
        'Local Capstone decoding of bytes retained by ' + refs['rsa_callback_bytes']['evidence_id'] + '\n'
        + 'Subject SHA256 ' + sha(crypto) + '\n' + asm + '\n', encoding='utf-8')
    assert '0x800000000000001a' in asm and 'call 0x868c' in asm

    # Retain readable pseudocode only for entries that actually resolved to the
    # requested function; a failed REA item must not be accepted by its status.
    retained = HERE / 'pseudocode'
    retained.mkdir(exist_ok=True)
    index, ignored = [], []
    for session in ['rea-key-peim', 'rea-smm', 'rea-crypto']:
        for p in sorted((HERE / session / 'responses').glob('*.json')):
            obj = read_json(p).get('result', {}).get('structuredContent', {})
            nr = obj.get('normalized_result')
            if not isinstance(nr, dict):
                continue
            for item in nr.get('items', []):
                if 'pseudocode' not in item:
                    continue
                proc = item.get('procedure', {})
                if proc.get('status') != 'resolved' or proc.get('address') != item.get('address'):
                    ignored.append(dict(path=str(p), evidence_id=obj.get('evidence_id'),
                                        requested=item.get('address'), procedure=proc.get('status'),
                                        reason='Unresolved requested function; any returned pseudocode is excluded.'))
                    continue
                out = retained / f"{session}-{item['address'][2:]}.c"
                out.write_text(item['pseudocode'], encoding='utf-8')
                index.append(dict(path=str(out), sha256=sha(out.read_bytes()), address=item['address'],
                                  evidence_id=obj['evidence_id'], subject_sha256=obj['subject']['digest']['sha256']))
    (HERE / 'pseudocode_index.json').write_text(json.dumps(index, indent=2) + '\n')

    bundles = []
    for name in ['rea-key-peim', 'rea-smm', 'rea-crypto']:
        folder = HERE / name
        bundle = folder / 'evidence.json'
        assert bundle.exists() and (folder / 'stop-session').exists() and (folder / 'close-finally.json').exists()
        bundles.append(dict(session=name, export=str(bundle), sha256=sha(bundle.read_bytes()),
                            close_record=str(folder / 'close-finally.json'), controller_stopped=True))
    findings = [
        dict(id='HERO_CAP_AUTH', severity='release_blocker',
             finding='官方3107的固件签名和证书签名均有效；RC2保留的证书签名有效，但固件签名无效。',
             evidence=['hero_capsule_authentication.json', 'hero_openssl_authentication.json'],
             detail='独立纯Python RSA/PSS与OpenSSL结果一致。RC2改动属于被签名的ROM表区域8；未重签。'),
        dict(id='HERO_SIGNED_RANGE', severity='confirmed',
             finding='HERO自身SMM代码确认实际签名输入规则。',
             code='3370A4BD: 0x2e74', evidence_ids=[refs['signed_stream']['evidence_id']],
             detail='遍历24字节ROM表项，按表顺序选择attributes & 0x200的区域，并追加含零终止项的表。CAP flags位1(0x2)置位时还加入头部0x38字节，但这两份HERO的flags=0x10001，该位未置位。'),
        dict(id='HERO_ROOT_SOURCE', severity='confirmed_static',
             finding='根密钥存在于HERO本身的FFS，并通过PEIM建立的GUID HOB传递到CryptoSmm。',
             code=['76864548 TE-derived view: 0x2b9, 0x3ba', '2AD511C7: 0x1e74, 0x21f4, 0x1f38, 0x2014'],
             evidence_ids=[refs[k]['evidence_id'] for k in ['root_ffs_read', 'root_publication', 'crypto_hob_read_and_getkey']],
             detail='PEIM在FV 61c0f511-a691-4f54-974f-b9a42172ce53找RAW section；候选FFS按顺序为5b85965c、3a666558、3feec852。当前原CAP未发现前两种GUID，根RSA公钥FFS 3feec852位于CAP 0x1f011b8，RAW modulus位于0x1f011d4，与证书块根公钥完全一致。PEIM建立HOB 4e0f9bd4-e338-4b26-843e-bd3ad9b2837b，CryptoSmm读取其类型/长度/密钥并复制至分配的内存。此为静态路径，不是这台机器当前HOB的实测转储。'),
        dict(id='HERO_CRYPTO_DISPATCH', severity='confirmed_static',
             finding='SMM消费者使用HERO自身CryptoSmm协议完成根钥比较与双层RSA签名验证。',
             code=['2AD511C7: 0x2274, protocol table RVA0xe110', '3370A4BD: 0x2538, 0x31d4'],
             evidence_ids=[refs[k]['evidence_id'] for k in ['crypto_protocol_install', 'crypto_hob_read_and_getkey', 'certificate_and_firmware_verify', 'smm_init_and_error_propagation']],
             detail='CryptoSmm安装91abc830-16fc-4d9e-a189-5fc8bb411402，SMM定位该协议。先验证根钥/签署第一RSA块的证书；当前flags&4为0，所以证书摘要覆盖CAP[0x20,0x248)。再以第一块公钥验证CAP 0x148处的固件签名，摘要由0x2e74生成。'),
        dict(id='HERO_SECURITY_ERROR', severity='confirmed_static',
             finding='验签错误会向上传递并清除待更新状态；没有在所追路径中变成成功。',
             code=['2AD511C7 RSA callback: 0x1d04..0x1e71 (raw instructions)', '3370A4BD: 0x31d4 -> 0x33b8 -> 0x19d0'],
             evidence_ids=[refs[k]['evidence_id'] for k in ['rsa_callback_bytes', 'certificate_and_firmware_verify', 'capsule_dispatch', 'smm_init_and_error_propagation']],
             detail='flags&1+1在当前CAP给出模式2；回调PSS分支传8字节salt与0x800位长度。回调0x1e39..0x1e51把非零校验结果映射为0x800000000000001a。0x31d4/0x33b8保留错误；0x19d0遇该错误清除0x5210、0x5218、0x5228并返回。特殊0x19兼容状态的处理不会接受0x1a。未追踪最终EZ Flash文字错误提示映射，亦未在主板上调用这些函数。'),
        dict(id='HERO_FLASHBACK_LIMIT', severity='unknown',
             finding='USB BIOS FlashBack外部控制器采用什么验签策略仍未知。',
             detail='这些证据涵盖HERO固件内的SMM更新服务和公钥数学，不包括FlashBack外部控制器的实现、熔丝、板上当前密钥或真实刷写行为。不得由此单独断言FlashBack必定接受或必定拒绝。'),
    ]
    report = dict(
        status='BOUNDED_STATIC_REVIEW_COMPLETE_RC2_CAP_SIGNATURE_INVALID',
        scope='HERO3107/RC2 pinned bytes, Python/OpenSSL mathematics, three static REA sessions; no BMC connection, device access, flash, signing, or CAP mutation.',
        official_sha256=math_report['files']['original']['sha256'],
        rc2_sha256=math_report['files']['rc2']['sha256'],
        signature_result=dict(official_firmware=True, official_certificate=True, rc2_firmware=False, rc2_certificate=True),
        capsule_header_bytes=4096, rom_bytes=33554432,
        scheme='RSA-2048 / RSASSA-PSS / SHA-256 / MGF1-SHA256 / 8-byte salt',
        rom_map=dict(entries=18, end_including_terminator='0x620', gap_body_start='0x1070000', gap_length='0x10000'),
        findings=findings, evidence=refs,
        authentication_modules_identical_official_vs_rc2=modules,
        te_analysis_view_manifest=view,
        rsa_callback_decode=dict(rea_evidence_id=refs['rsa_callback_bytes']['evidence_id'],
                                 method='Local Capstone over exact REA read_bytes output; not REA pseudocode.',
                                 capstone_version=capstone.__version__, bytes_match_original_pe=True,
                                 disassembly=str(HERE / 'crypto_rsa_callback_disassembly.txt')),
        ignored_inconsistent_decompile_items=ignored,
        raw_evidence_bundles=bundles,
        retained_pseudocode_index=str(HERE / 'pseudocode_index.json'),
        report_bindings=[dict(path=str(HERE / name), sha256=sha((HERE / name).read_bytes())) for name in
                         ['hero_capsule_authentication.json', 'hero_openssl_authentication.json', 'rootkey_pe_view_manifest.json']],
        limitations=[
            'Static decompilation records are shipped-artifact evidence, not execution or successful hardware authentication.',
            'PEIM evidence subject is a derived PE view of an IA32 TE; section bytes/RVAs are preserved, with TE source and derived hashes retained.',
            'REA did not resolve CryptoSmm callback0x1d04 as a function; a batch item returned unrelated pseudocode despite unknown procedure. That pseudocode is excluded, exact read_bytes evidence is used with local disassembly instead.',
            'No live installed root-key/HOB snapshot was captured, and no internal verifier was invoked with RC2 on hardware by this reviewer.',
            'No claim is made that FlashBack uses this SMM service or that absence of a programmer is a recovery guarantee.',
            'No new firmware feature or boot/sensor/menu behavior is proven by capsule signature validation.',
        ])
    output = HERE / 'hero_capsule_rea_review.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    text = ('HERO 3107 / P5 RC2 CAP认证复核（2026-11-04）\n\n'
            '结论：原版两层签名通过；RC2证书签名通过，固件签名失败。不能将RC2标为已认证或已刷写通过。\n'
            '签名：RSA-2048 / PSS / SHA-256 / MGF1-SHA256，salt=8字节；纯Python与OpenSSL两套验证一致。\n'
            '覆盖：HERO自身SMM反编译确认ROM表中attributes & 0x200的区域按表顺序连同终止表项签入摘要。'
            'RC2修改位于被签名的DXE区域8（CAP 0x12d1000，长0x9f0000）。\n'
            '根钥：HERO自身3feec852公钥FFS -> 76864548 PEIM -> 4e0f9bd4 GUID HOB -> 2AD511C7 CryptoSmm -> 3370A4BD SMM更新服务。'
            '这三个模块在官方与RC2中逐字节相同。\n'
            '拒绝路径：加密校验失败返回EFI_SECURITY_VIOLATION (0x800000000000001a)，上层保留错误并清除待更新状态。\n'
            '边界：以上是静态代码与本地公钥数学结果；没有执行设备上的内部验签函数，没有刷写。'
            'USB BIOS FlashBack外部控制器策略仍未知，不能据此断言它必定接受或拒绝。\n\n'
            '官方SHA256：' + report['official_sha256'] + '\nRC2 SHA256：' + report['rc2_sha256'] + '\n'
            '详细结论与真实REA Evidence ID：hero_capsule_rea_review.json\n'
            '数学结果：hero_capsule_authentication.json；OpenSSL结果：hero_openssl_authentication.json\n'
            '原始REA证据：rea-key-peim/evidence.json、rea-smm/evidence.json、rea-crypto/evidence.json。三会话已关闭。\n')
    (HERE / 'HERO-CAP-认证复核结论.txt').write_text(text, encoding='utf-8')
    print(json.dumps(dict(output=str(output), sha256=sha(output.read_bytes()),
                          status=report['status'], evidence_count=len(refs), closed_sessions=len(bundles)), indent=2))


if __name__ == '__main__':
    main()
