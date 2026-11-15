"""Verify all existing engineering-only inputs and emit a public delivery index.

Never signs or regenerates a key/image. No hardware or network access.
"""
import sys
sys.dont_write_bytecode = True
from capsule_common import *


def main():
    creation_path = HERE/'creation_manifest.json'; verification_path = HERE/'verification.json'
    creation = json.loads(creation_path.read_text(encoding='utf8')); verification = json.loads(verification_path.read_text(encoding='utf8'))
    assert verification['status'] == 'PASS_ENGINEERING_ONLY_DUAL_SIGNATURE_CROSSCHECK_NOT_FLASH_READY'
    assert verification['engineering_artifact'] == creation['artifact'] == record(ARTIFACT)
    assert verification['creation_manifest'] == record(creation_path)
    assert verification['source_stale_signature'] == creation['source'] == record(SOURCE)
    assert verification['original'] == record(ORIGINAL)
    assert verification['script'] == record(HERE/'verify_engineering.py')
    assert verification['common'] == creation['common'] == record(HERE/'capsule_common.py')
    assert creation['script'] == record(HERE/'sign_engineering.py')
    assert verification['pure_python_verifier'] == record(HELPER)
    assert verification['openssl'] == record(OPENSSL) and verification['libcrypto'] == creation['libcrypto'] == record(LIBCRYPTO)
    assert verification['check_count'] == 17 and verification['negative_controls_rejected_by_both_verifiers'] == 11
    for case in verification['checks']:
        assert case['python']['valid'] == case['expected_valid'] == (case['openssl']['returncode'] == 0)
        for key in ['public_key', 'signature', 'digest']:
            item = case[key]; assert record(ROOT/item['path']) == item
    scope = parser(); _, source, _ = inputs(scope)
    assert preservation(scope, source, ARTIFACT.read_bytes()) == verification['preservation']
    public_key_files = list((HERE/'public_evidence').glob('*.pem'))
    assert public_key_files and all(p.read_bytes().startswith(b'-----BEGIN RSA PUBLIC KEY-----\n') for p in public_key_files)
    assert not list(HERE.rglob('*.pfx')) and not list(HERE.rglob('*.p12')) and not list(HERE.rglob('*.key'))
    signed = verification['independent_raw_map_digests']['engineering_nonOEM']['included_ranges_in_table_order']
    assert len(signed) == 10 and sum(x['bytes'] for x in signed) == 12709839
    native_path = HERE.parent/'update_path_reference/bmc1313_engineering_signature_replay.json'
    assert sha(native_path.read_bytes()) == '152c716ff7a53f25fa6355b75314bdb0fd0d025e7bad353fcba8a87bf75daa19'
    native = json.loads(native_path.read_text(encoding='utf8'))
    assert native['status'] == 'PASS_ENGINEERING_CAP_CURRENT_1313_NATIVE_PDK_ONLY_NOT_FLASH_READY'
    assert native['input'] == record(ARTIFACT) and native['baseline']['sha256'] == SOURCE_SHA
    assert sha((ROOT/native['source']['path']).read_bytes()) == native['source']['sha256']
    assert native['payload_byte_identical_to_baseline'] and native['payload_sha256'] == verification['preservation']['payload_candidate_sha256']
    assert native['native_return'] == 0 and native['native_instructions'] == 846 and native['native_import_links'] == ['read_file_append']
    assert len(native['crypto']) == 2 and all(row['verification']['valid'] for row in native['crypto'])
    digests = verification['independent_raw_map_digests']['engineering_nonOEM']['digests']
    assert native['crypto'][0]['verification']['message_digest'] == digests['certificate']
    assert native['crypto'][1]['verification']['message_digest'] == digests['firmware']
    assert native['BMC_access'] is False and native['candidate_modified'] is False
    readme = '''ACE1904 candidate05 工程签名候选：非 ASUS/OEM 签名，NOT FLASH READY

这是用自有一次性工程密钥真实重签的 Capsule，仅供离线审查。
没有声称 ASUS 授权、OEM 签名或设备信任；没有更新驻留信任锚、修改验证代码、改变签名flag或缩减签名范围。
本目录没有执行 BMC 上传、固件更新、刷写、重启或设备密钥注册。

输入：flash_candidate05/lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.bin
输入 SHA256：9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455
产物：W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP
产物 SHA256：e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08
产物总长：67112960字节（4096字节Capsule头 + 67108864字节payload）。
完整payload SHA256：2dd240c1ddb8890500ce028bb7de25d2db8f687117f4c0d2a57ba400ffbe9809
输入/输出从0x1000至文件末尾逐字节一致；设备固件中的验证逻辑、公钥、密钥存储及全部其他payload字节均未修改。

按原始格式保留 flags=0x10001、证书类型/GUID、两个SHA256 GUID、各长度/偏移、原ROM map及全部属性。
仅允许变更以下4个半开区间，实际改变1014字节：
CAP[0x48:0x148] 固件签名工程公钥模数；CAP[0x148:0x248] 固件签名。
CAP[0x258:0x358] 证书签名工程公钥模数；CAP[0x358:0x458] 证书签名。
新增的嵌入公钥属于本工程，不是对设备驻留信任锚的登记或替换。

两层均为RSA2048 / PSS / SHA256 / MGF1-SHA256 / salt8 / exponent65537。
先签固件，再签证书。固件摘要按原map表序拼接属性bit0x200置位的10个区，共12709839字节，再附原map的552字节（包含24字节零终止项）。
证书摘要为完成固件签名之后的CAP[0x20:0x248]。这保持原格式，并非声称原签名规则认证整个64MiB。
完整64MiB一致性由独立逐字节比较和全payload SHA256另外证明。

两把不同角色密钥由本机OpenSSL libcrypto4.0.2原生EVP对象新生成，仅存在于签名进程内存。
未读取d/p/q等私钥参数，未导出或序列化私钥，未创建临时私钥文件，也未放入命令行、环境或子进程输入输出。
只导出公共n/e与签名；EVP对象已释放，签名进程已退出。不宣称操作系统内存/分页的安全擦除。
私钥没有留存，因此不能继续使用本次密钥签发新版。重新制作必须生成新键并产生新的镜像哈希；脚本拒绝覆盖现有候选。
public_evidence只保留公钥、签名和摘要，可公开复核，不包含本次私钥。

验证结果：纯Python整数RSA/PSS数学与独立OpenSSL CLI共17个交叉检查全部符合预期。
原厂：固件/证书2签均有效；旧candidate05：固件签失效、原证书签有效；新工程候选：工程固件/证书2签均有效。
11个反例被两种验签器共同拒绝：OEM公钥下工程签名无效、签名字节改变、摘要改变、角色公钥互换、签名覆盖payload改变、map改变、固件签后证书覆盖关系改变。
摘要还由本目录原始字段解析独立计算，结果与固定哈希的纯验证helper一致。
完整报告见verification.json；可复核命令：Python verify_engineering.py。
sign_engineering.py --preflight只核对输入/格式/API；--create只允许在无现有产物时生成，不能作为复核命令重复执行。
finalize_engineering.py只绑定现有证据，不签名、不重建。

上游参考：当前ACE原厂及1.3.13格式证据位于../update_path_reference/。
OpenSSL签名API文档：https://docs.openssl.org/3.6/man3/EVP_PKEY_sign/
纯数学验证helper固定SHA256 fc7348a36ba77cf100095db89de12e6f45963ed456b962c876839160fbe693c2，只通过AST提取纯函数，未执行旧main。

另一审查代理已对当前1.3.13 PDK及read_file_append真实ARM指令作独立离线回放：846条指令，返回0，两次公钥验签均通过。
报告../update_path_reference/bmc1313_engineering_signature_replay.json，SHA256 152c716ff7a53f25fa6355b75314bdb0fd0d025e7bad353fcba8a87bf75daa19。
文件操作为隔离RAM模型；crypto导入由数学公钥验证实现，未执行BMC或ARM OpenSSL二进制。
此证据只覆盖Capsule双签谓词，不等同实机BMC接受，也不覆盖驻留根的后续尾签或完整更新链。
仍未证明：实机驻留公钥策略、完整更新链接受、成功刷写及冷启动、设备专属数据保留、断电或BIOS失效后的可用恢复途径。
本候选的明确状态是工程签名已验证、非OEM、NOT FLASH READY。
'''
    (HERE/'README-工程签名候选.txt').write_text(readme, encoding='utf8')
    files = [p for p in sorted(HERE.rglob('*')) if p.is_file() and p.name != 'delivery_manifest.json' and '__pycache__' not in p.parts]
    report = {'status': 'REVIEWABLE_ENGINEERING_SIGNATURE_ARTIFACT_NOT_FLASH_READY', 'engineering_artifact': record(ARTIFACT),
              'source': record(SOURCE), 'payload_sha256': verification['preservation']['payload_candidate_sha256'],
              'payload_bytes': 67108864, 'payload_byte_identical': True, 'changed_header_bytes': 1014,
              'local_dual_verifier_checks': 17, 'negative_controls': 11, 'public_key_only_pem_files': len(public_key_files),
              'private_key_file_created_or_retained': False, 'ASUS_signature': False, 'BMC_uploaded': False,
              'device_trust_anchor_changed': False, 'verifier_changed': False, 'signature_flags_or_ranges_changed': False,
              'FLASH_READY': False,
              'native_PDK_instruction_replay': {'report': record(native_path), 'return': 0, 'native_instructions': 846,
                                                'scope': 'Current official1.3.13 PDK/read_file_append ARM instructions, closed RAM file model, mathematical crypto imports; not live BMC acceptance'},
              'files': [record(path) for path in files]+[record(native_path)]}
    save(HERE/'delivery_manifest.json', report)
    print(json.dumps({'status': report['status'], 'artifact': record(ARTIFACT), 'manifest': record(HERE/'delivery_manifest.json'),
                      'readme': record(HERE/'README-工程签名候选.txt'), 'public_only_files': len(files)}, indent=2))


if __name__ == '__main__': main()
