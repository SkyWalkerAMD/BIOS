"""Bind the selected static REST handler observations to the official artifact."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import re

HERE = Path(__file__).resolve().parent

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    binary = HERE/'bmc_backend/5308416/usr/local/bin/spx_restservice'
    decomp = HERE/'rest_decompile'
    inventory = json.loads((decomp/'function_inventory.json').read_text())
    assert inventory['executable_sha256'] == sha(binary)
    binding = json.loads((HERE/'frontend_binding.json').read_text())
    assert binding['deployed_frontend_exact_match'] is True
    selected = [f for f in inventory['functions'] if 'decompile_completed' in f]
    assert len(selected) == 23 and all(f['decompile_completed'] for f in selected)
    observations = []
    specs = [
        ('VerifySignature_func', 'CMD_Verify_BIOS_Signature(',
         '正常验签 REST handler 调用组件层验签，并按返回状态输出成功或错误；不是仅在浏览器中校验文件扩展名。'),
        ('setBIOSPrepareComponents_func', 'CMD_Prepare_FW_Update(',
         '准备 handler 调用组件更新准备函数；该调用的硬件副作用须从组件库继续追踪，不能由 HTTP PUT 名称判断为只读。'),
        ('putBIOSStartFlashMode_func', 'CMD_Start_Firmware_Update(',
         '刷写 handler 调用组件固件更新函数；本次没有调用此 handler。此层单独出现验签接口不等于整条链已强制绑定验签结果。'),
        ('downloadBackupConfig_func', 'LIBIPMI_HL_AMIGetPendStatus(',
         '配置下载 handler 等待 BMC 配置打包状态后返回下载响应；不能作为主板完整 SPI 导出的证据。'),
    ]
    for name, anchor, description in specs:
        f = next(x for x in selected if x['name'] == name)
        path = decomp/f['pseudocode_file']
        content = path.read_text()
        assert anchor in content
        observations.append({'function':name, 'address':f['address'], 'description_zh':description,
                             'path':str(path.relative_to(HERE)), 'sha256':sha(path),
                             'anchor':anchor, 'line':content[:content.index(anchor)].count('\n')+1})
    routes = []
    for m in re.finditer(rb'[\x20-\x7e]{5,}', binary.read_bytes()):
        value = m.group().decode('ascii')
        if value.startswith('/api/maintenance/') or (value.startswith('/api/') and 'bios' in value.lower()):
            routes.append({'path':value, 'file_offset':hex(m.start())})
    result = {
        'status':'STATIC_REST_REVIEW_COMPLETE_NO_FULL_HOST_SPI_EXPORT_ESTABLISHED',
        'generated_utc':datetime.now(timezone.utc).isoformat(),
        'target':'W790E-SAGE SE, BMC 1.1.57, official W7901157.ima',
        'backend_source_sha256':sha(binary),
        'deployed_frontend_exact_match':True,
        'backend_identity_limit':'The public image is version-bound by exact deployed frontend bytes; remote backend executable bytes have not been read back.',
        'analysis_method':'REA ELF/Windows capability rejection recorded; fallback to installed Ghidra 12.1.4 headless, ARM:LE:32:v8, no target execution.',
        'selected_handler_count':len(selected),
        'observations':observations,
        'maintenance_and_bios_route_literals':routes,
        'full_spi_export_found_in_reviewed_routes':False,
        'limits':[
            'A bounded static route/handler review is not proof that every possible service or hidden route is absent.',
            'Computed jumps and unknown C types remain decompiler limitations; retain machine code and literal-pool evidence.',
            'No firmware upload, update-mode entry, prepare, verification request or flash request was sent to the device.',
            'No claim is made that an unsigned candidate was actually rejected by this BMC, or that arbitrary no-POST recovery was tested.',
        ],
        'evidence':{str(p.relative_to(HERE)):sha(p) for p in [
            HERE/'official_bmc_source.json', HERE/'frontend_binding.json',
            HERE/'rea_bmc/rest-open.json', decomp/'function_inventory.json', decomp/'literal_pool.json',
            HERE/'BmcSelectedDecompile.java', HERE/'run_headless.py',
        ]},
    }
    (HERE/'rest_backend_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'status':result['status'], 'selected_handlers':len(selected),'route_literals':len(routes)}))

if __name__ == '__main__':
    main()
