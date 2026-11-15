"""Freeze an offline, evidence-bounded SendForm review. No target operations."""
from pathlib import Path
import argparse, hashlib, json, re, struct, sys, uuid, zlib

HERE = Path(__file__).resolve().parent
D04 = HERE.parent
ROOT = next(p for p in HERE.parents if (p / 'tools/kvm-pydeps').is_dir())
SAGE = ROOT / 'analysis/aitweaker_lock/lock_sage_1904'
HW = SAGE / 'remote_172_20_2_162'
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / 'tools/kvm-pydeps'), str(ROOT / 'tools/pydeps')]
from PIL import Image
import capstone, pefile, zxingcpp

MANIFEST = HERE / 'review_manifest.json'
REPORT = HERE / 'review.json'
TSE_HASH = '531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1'
EFI_HASH = '2092c11abfc1cc9271357277aaac030424f8dd99c342ae1612f4c0cd3d82e169'
ISO_HASH = '1841d9a227f11ca7cce4270b75a32213a37e4b772f9040f293133554516db5f8'
bindings = {}

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def bind(path):
    path = Path(path).resolve()
    assert path.is_relative_to(ROOT)
    rel = path.relative_to(ROOT).as_posix()
    bindings[rel] = {'path': rel, 'bytes': path.stat().st_size, 'sha256': sha(path)}
    return path

def read_json(path):
    return json.loads(bind(path).read_text(encoding='utf8'))

def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf8')

def raw_snapshot():
    folder = HW / 'hardware-native13-ram-test05-1793710255493-6348c6d6'
    original = read_json(folder / 'manifest.json')
    pieces = []
    identity = None
    for page in range(1, 4):
        png = bind(folder / f'page-{page:02}.png')
        frame = bind(folder / f'page-{page:02}.frame')
        codes = zxingcpp.read_barcodes(Image.open(png))
        assert len(codes) == 1
        raw = bytes(codes[0].bytes)
        assert raw == frame.read_bytes()
        header, payload = raw.split(b'\n\n', 1)
        m = re.fullmatch(rb'AITWK-P3-KVM\nT=(\d+);C=([0-9A-F]{8});P=(\d+)/(\d+);O=(\d+);N=(\d+);D=([0-9A-F]{8})', header)
        assert m
        total, crc, number, pages, offset, size, pcrc = m.groups()
        total, number, pages, offset, size = map(int, [total, number, pages, offset, size])
        assert number == page and pages == 3 and size == len(payload)
        assert pcrc.decode() == f'{zlib.crc32(payload) & 0xffffffff:08X}'
        key = total, crc.decode(), pages
        assert identity is None or identity == key
        identity = key
        assert offset == sum(len(x) for x in pieces)
        pieces.append(payload)
    log = b''.join(pieces)
    assert len(log) == identity[0] == original['bytes'] == 1901
    assert f'{zlib.crc32(log) & 0xffffffff:08X}' == identity[1] == original['crc32'] == '5086171C'
    assert hashlib.sha256(log).hexdigest() == original['sha256']
    assert log == bind(folder / 'hardware-log.txt').read_bytes()
    assert b'SNAPSHOT_ID=0000000000000003\r\n' in log
    assert b'LOG_COMPLETE=YES\r\n' in log and b'LOG_OVERFLOW=NO\r\n' in log
    return {'pages': 3, 'bytes': len(log), 'crc32': identity[1], 'sha256': original['sha256'],
            'snapshot_id': '0000000000000003',
            'scope': '重新解码原始3张PNG，与每页frame及完整log逐字节相等；这是按M之前的快照，不是SendForm返回日志。'}

def native_spans():
    module = bind(SAGE / 'analysis/modules/AMITSE.efi')
    assert sha(module) == TSE_HASH
    pe = pefile.PE(data=module.read_bytes())
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    spans = []
    # These are bounded source spans, not inferred whole-function CFGs.
    for name, start, end in [
        ('nested_entry_decision', 0x20f4b, 0x20f75),
        ('hii_selection', 0x21038, 0x210be),
        ('tpl_and_console_preparation', 0x210e0, 0x211b1),
        ('native_browser_and_display_return', 0x21257, 0x21368),
        ('optional_action_request_write', 0x21415, 0x21435),
        ('framebuffer_backup', 0x6d88, 0x6e3c),
        ('native_stage_width', 0xe1b8, 0xe1ed),
        ('original_outer_launch', 0x953c, 0x9614),
    ]:
        instructions = list(cs.disasm(pe.get_data(start, end-start), start))
        spans.append({'name': name, 'start_rva': hex(start), 'end_exclusive': hex(end),
                      'instructions': [{'rva': hex(i.address), 'bytes': i.bytes.hex(),
                                        'mnemonic': i.mnemonic, 'operands': i.op_str} for i in instructions]})
    expected_calls = {0x20f61: 0x21d3c, 0x20f6b: 0x453c4, 0x21075: 0x29d7c,
                      0x211ac: 0x6d88, 0x21257: 0x40bc, 0x2125c: 0xe1b8}
    for address, target in expected_calls.items():
        i = next(cs.disasm(pe.get_data(address, 15), address))
        assert i.mnemonic == 'call' and i.op_str == hex(target)
    stage = next(cs.disasm(pe.get_data(0xe1e2, 15), 0xe1e2))
    assert stage.mnemonic == 'mov' and stage.op_str.startswith('qword ptr [rip')
    cs.detail = True
    stage = next(cs.disasm(pe.get_data(0xe1e2, 15), 0xe1e2))
    assert stage.address + stage.size + stage.operands[0].mem.disp == 0x83468
    assert stage.operands[1].imm == 4
    assert pe.get_data(0x21427, 7).hex() == '48c70001000000'
    assert pe.get_data(0x6e2d, 4).hex() == '41ff5210'
    assert pe.get_data(0x21311, 4).hex() == '41ff5008'
    mapping = read_json(SAGE / 'navigation/sendform_mapping.json')
    assert mapping['module_sha256'] == TSE_HASH and mapping['reachable_instructions'] == 353
    assert mapping['same_masked_opcodes_and_relative_offsets'] and mapping['same_direct_branch_edges']
    write_json(HERE / 'exact_native_spans.json', {'module_sha256': TSE_HASH,
               'scope': '静态原始字节；没有执行ASUS浏览器。区间不等同完整控制流图。', 'spans': spans})
    return {'module_sha256': TSE_HASH, 'sage_sendform_rva': '0x20ee4',
            'ace_reference_entry': '0x20f34', 'mapped_reachable_instructions': 353,
            'same_masked_opcodes_and_direct_edges': True}

def package_structure():
    data = bind(D04 / 'provider13/build/management.pack').read_bytes()
    assert len(data) == 991 and struct.unpack_from('<I', data, 16)[0] == len(data)
    assert sha(bind(D04 / 'provider13/source/management_package.h')) == sha(bind(D04 / 'readonly_browser_baseline06/source/management_package.h'))
    packages, opcodes, actions = [], [], []
    pos = 20
    while pos < len(data):
        value = struct.unpack_from('<I', data, pos)[0]
        size, kind = value & 0xffffff, value >> 24
        assert size >= 4 and pos + size <= len(data)
        packages.append({'type': hex(kind), 'offset': pos, 'bytes': size})
        if kind == 2:
            cursor = pos + 4
            scopes = 0
            while cursor < pos + size:
                opcode, flags = data[cursor:cursor+2]
                length, scope = flags & 0x7f, flags >> 7
                assert length >= 2 and cursor + length <= pos + size
                opcodes.append({'offset': cursor, 'opcode': hex(opcode), 'bytes': length, 'scope': scope})
                if opcode == 14:
                    assert length == 23 and data[cursor+22] == 0
                    formset = str(uuid.UUID(bytes_le=data[cursor+2:cursor+18]))
                elif opcode == 1:
                    form = struct.unpack_from('<H', data, cursor+2)[0]
                elif opcode == 12:
                    prompt, help_, qid, store, offset, question_flags, config = struct.unpack_from('<5HBH', data, cursor+2)
                    assert length == 15 and store == 0 and offset == 0xffff and question_flags == 4 and config == 0
                    actions.append({'question_id': hex(qid), 'prompt_id': prompt, 'help_id': help_, 'flags': question_flags})
                if opcode == 0x29:
                    scopes -= 1
                    assert scopes >= 0
                scopes += scope
                cursor += length
            assert cursor == pos+size and scopes == 0
        if kind == 4:
            header_size = struct.unpack_from('<I', data, pos+4)[0]
            language = data[pos+46:pos+header_size].split(b'\0')[0].decode('ascii')
        if kind == 0xdf:
            assert size == 4 and pos+size == len(data)
        pos += size
    assert pos == len(data) and [p['type'] for p in packages] == ['0x2', '0x4', '0xdf']
    assert [x['opcode'] for x in opcodes] == ['0xe', '0x1', '0x3', '0xc', '0xc', '0xc', '0x29', '0x29']
    assert formset == 'b16b94e6-99f4-4f60-8f7b-b6d234e4a513' and form == 1
    assert [a['question_id'] for a in actions] == ['0xffe0', '0xffe1', '0xffe2'] and language == 'en-US'
    result = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
              'package_guid': str(uuid.UUID(bytes_le=data[:16])), 'formset_guid': formset,
              'form': form, 'class_guids': [], 'language': language,
              'packages': packages, 'ifr_opcodes': opcodes, 'actions': actions,
              'varstore_opcodes': [], 'scope': '独立解析结构；结构符合已固定布局不证明ASUS实际渲染兼容。'}
    write_json(HERE / 'hii_structure.json', result)
    return result

def freeze():
    assert not REPORT.exists() and not MANIFEST.exists(), 'Frozen output already exists; use --verify-only.'
    snapshot, native, package = raw_snapshot(), native_spans(), package_structure()
    key = read_json(HW / 'native-test09-key-1793710307009-155a60fe-result.json')
    off = read_json(HW / 'ram-test09-off-1793710385549-d4ac21f1-result.json')
    for row in [key, off]:
        assert sha(bind(HW / row['evidence'])) == row['evidence_sha256']
    assert key['key'] == 'm' and key['key_sent'] and not key['automatic_retry']
    image = Image.open(HW / off['evidence']).convert('RGB')
    assert image.size == (1600, 1200)
    assert image.crop((400, 76, 1200, 676)).getextrema() == ((0, 0), (0, 0), (0, 0))
    counter = read_json(D04 / 'guard_blackout_review01/native_static_control_counterexample.json')
    assert counter['checks'] == 24 and counter['original_sha256'] == TSE_HASH
    assert all(x['opcode'] == 2 and x['initial_hii'] == '0xffffffffffffffff' and x['classification_before'] == 'UNKNOWN' for x in counter['cases'])
    candidate = read_json(D04 / 'readonly_browser_baseline06/candidate_manifest.json')
    assert candidate['efi_sha256'] == EFI_HASH and candidate['iso_sha256'] == ISO_HASH
    rea_log = [json.loads(x) for x in (HERE / 'rea/plan.mcp-stderr.txt').read_text(encoding='utf8').splitlines() if x.strip()]
    assert [(x['tool'], x['status']) for x in rea_log] == [('open_binary', 'ok'), ('analyze_function', 'error'), ('close_binary', 'ok')]
    assert rea_log[1]['durationMs'] == 180647.72
    provenance = read_json(D04 / 'provider13_ovmf_lab/reference/browser_provenance.json')
    for row in provenance['files']:
        assert sha(bind(row['path'])) == row['sha256']
    for path in [
        D04 / 'provider13_ovmf_lab/persist_ui.c', D04 / 'provider13_ovmf_lab/fixture_extra.inc',
        D04 / 'provider13/build_hii.py', D04 / 'provider13/build/management_package.json',
        D04 / 'ram_transaction05/source/session_ui.c',
        D04 / 'readonly_browser_baseline06/source/browser.c',
        D04 / 'readonly_browser_baseline06/candidate_review.json',
        D04 / 'readonly_browser_baseline06_independent_review/independent_review.json',
        D04 / 'readonly_browser_baseline06_independent_review/independent_manifest.json',
        ROOT / 'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/rea/AMITSE-Seeded-SendForm.c',
    ]:
        bind(path)
    report = {
        'status': 'FROZEN_OFFLINE_SEND_FORM_DIFFERENTIAL_REVIEW',
        'target': 'ASUS Pro WS W790E-SAGE SE BIOS 1904',
        'target_actions_by_reviewer': False, 'physical_black_screen_cause_proven': False,
        'password_acceptance': False, 'release_ready': False,
        'physical_evidence': {'pre_m_snapshot': snapshot, 'm_key_utc': key['utc'],
            'black_screen_observation': {'screenshot': off['evidence'], 'record_utc': off['utc'],
                'black_rectangle_pixels': [400, 76, 1200, 676], 'black_rectangle_size': [800, 600],
                'scope': '人工复看截图并核对该矩形全黑；不是CPU状态、故障位置或实际GOP模式读回。'},
            'off_record_scope': 'ForceOff请求202，记录明确readback pending；本报告不据此声明最终关机状态。',
            'esc_scope': '父任务报告单Esc后仍黑；本报告未额外绑定该按键的独立原始记录。'},
        'native_mapping': native,
        'findings': [
            {'id': 'VM_SCOPE', 'confidence': 'CONFIRMED_FIXTURE_SOURCE',
             'detail': '旧P13 OVMF的browser_body调用OVMF FormBrowser2；run_step经原E1B8包装入口后由TCG #DB重定向到声明的替代body。真实ASUS SendForm20EE4及其原生页面构建、显示和输入链未被该fixture执行。它仍验证真实provider/UI/NVRAM持久化，但不证明ASUS GUI兼容。'},
            {'id': 'HII_AND_ABI', 'confidence': 'CONFIRMED_STRUCTURE_AND_PINNED_HEADER',
             'detail': '同一991B包有一个独立formset、Form1、三个ACTION，零class GUID且无varstore。FormBrowser2头允许指定formset GUID、FormId和可选屏幕区域；未见禁止独立表单的接口条件。标准布局有效不保证本厂商内部初始化条件齐备。',
             'package_sha256': package['sha256']},
            {'id': 'NESTED_AND_LAUNCH', 'confidence': 'CONFIRMED_STATIC_BRANCHES',
             'detail': '20F4B/20F54检查native app指针和另一入口状态字节，20F61走21D3C保存嵌套上下文，20F6B加载专有表单数据；失败可到20FDC的EFI_UNSUPPORTED。快照的outer return960C仅证明特定F8启动调用链，不能证明原生浏览器实例不存在或等同直接Del启动。'},
            {'id': 'DISPLAY_PATH', 'confidence': 'CONFIRMED_STATIC_BOUNDARY_WITH_LIMIT',
             'detail': 'SendForm保存ConsoleControl/GOP/文本模式并在2125C进入原E1B8，返回后才有2129B文本SetMode、21311 GOP SetMode和2135E ConsoleControl恢复。211AC调用6D88是GOP VideoToBuffer备份（6E2D调用Blt+10、operation1），不是GOP SetMode。截图800x600与原生显示准备相容，但不能确定在哪条指令改变分辨率或停住。'},
            {'id': 'ACTION_REQUEST', 'confidence': 'CONFIRMED_STATIC_CALLER_DIFFERENCE',
             'detail': '原20EE4在21415检查reset状态后仅于21427条件写ActionRequest=1；已检查路径未见无reset时主动写NONE。旧9115调用端把初值设为~0，可能在正常返回时误判；06初始化NONE。该问题发生在返回校验，不能解释当前返回前黑屏。'},
            {'id': 'STATIC_CONTROL_COMPATIBILITY', 'confidence': 'CONFIRMED_NATIVE_CODE_COUNTEREXAMPLE_NOT_PHYSICAL_TRACE',
             'detail': '另一个agent的24项实际构造函数检查确认：kind1/2/3/5静态SUBTITLE(02,length7)先有HII=-1。原171D4稍后赋真实HII，但冻结guard在原render前就按HII归属拒绝。它证明原生控件生命周期与guard分类不兼容；尚未读取黑屏时实际frame/control，不能把它等同物理原因。',
             'evidence': 'guard_blackout_review01/native_static_control_counterexample.json',
             'evidence_sha256': sha(D04 / 'guard_blackout_review01/native_static_control_counterexample.json')},
        ],
        'diagnostic_candidate': {'efi_sha256': EFI_HASH, 'iso_sha256': ISO_HASH,
            'contract': '06同一HII包、原始SendForm同GUID/Form1、无guard/provider/密码函数。仅B一次；三个ConfigAccess方法只记录有限数字元数据并拒绝；Q回收。先后完整原.text/头/12点身份、私有变量缺失和OC/MEM只读核对；事件/TPL边界、资源驻留。',
            'limits': '生命周期回调也拒绝可能自身影响浏览器。注册协议/HII和原厂SendForm有标准volatile及未知OEM内部副作用，不宣称系统零写入。若再次不返回，RAM日志无法在断电后恢复。本报告不包含06任何实机结果。'},
        'rea_attempt': {'state': 'ANALYZE_FUNCTION_TIMEOUT_NO_NEW_DECOMPILATION',
            'detail': '固定local REA对未改AMITSE+分析种子成功open，analyze_function记录180647.72ms error，finally close_binary记录ok；没有新的20EE4反编译结果。保留原日志；结论使用已有ACE REA输出、353指令映射与精确SAGE机器码，不把超时当成功。'},
        'next_evidence': ['单独06基线的实际页面显示、Esc返回和前后日志。',
            '若纯原厂表单成功，按真实静态控件构造语义修guard，重新绑定新版本并再次测试；不能从基线成功直接验收密码锁。',
            '永久Security入口和每次Del/F2开机自动安装、实际密码生命周期、闪存信任/恢复仍是独立未完成项。']}
    write_json(REPORT, report)
    (HERE / 'README.md').write_text(
        '原生 SendForm 黑屏差异审查已冻结。实机按 M 前的三页二维码（1901 B，CRC 5086171C）已重新从 PNG 解码并逐字节核对；随后截图可确认 800×600 黑色画面，不能据此认定 CPU hold。\n\n'
        '旧 OVMF 测试执行真实 provider 和 OVMF 表单浏览器，但用显式 body fixture 代替 ASUS 原始页面构建/渲染/输入链。它没有覆盖这次关键厂商路径。\n\n'
        '现已确认原厂静态 SUBTITLE 控件先带 HII=-1、原 render 稍后赋值；冻结 guard 提前拒绝这种真实构造结果。这是可复现兼容缺陷，尚不是黑屏现场的执行轨迹。另发现原 SendForm 不总把 ActionRequest 写成 NONE，06 已用 NONE 初值避免正常返回误判；该差异不能解释返回前黑屏。\n\n'
        '06 候选2092c11a… / ISO1841d9a2…用于单独验证无guard/provider时同一独立HII包的原厂SendForm。其动作回调均拒绝，生命周期回调拒绝也可能影响厂商行为。测试结果不能替代密码、永久菜单或直接Del/F2启动集成验收。\n\n'
        '本轮新 REA analyze_function 超时，原日志及关闭结果保留；没有声称取得新的反编译结果。证据来自已有REA输出、精确SAGE指令映射、原始字节、独立包结构解析和现有冻结测试。\n', encoding='utf8')
    for p in HERE.rglob('*'):
        if p.is_file() and p != MANIFEST and not any(x in ['tmp', '__pycache__'] for x in p.parts):
            bind(p)
    write_json(MANIFEST, {'path_base': 'workspace_root', 'status': report['status'],
                          'artifacts': sorted(bindings.values(), key=lambda x: x['path'])})
    verify()

def verify():
    manifest = json.loads(MANIFEST.read_text(encoding='utf8'))
    for row in manifest['artifacts']:
        path = ROOT / row['path']
        assert path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], str(path)
    print(json.dumps({'status': 'PASS_FROZEN_SEND_FORM_REVIEW_BINDINGS',
                      'bindings': len(manifest['artifacts']), 'manifest_sha256': sha(MANIFEST),
                      'report_sha256': sha(REPORT)}))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    verify() if args.verify_only else freeze()
