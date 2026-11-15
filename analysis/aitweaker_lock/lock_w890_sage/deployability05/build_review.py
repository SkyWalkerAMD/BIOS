"""Assemble precise offline BMC deployment findings; never produce a release."""
from pathlib import Path
import datetime,hashlib,json
HERE=Path(__file__).resolve().parent

def bind(p):
    data=p.read_bytes();return {'path':str(p.resolve()),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
def read(p):return json.loads(p.read_text(encoding='utf-8'))

def main():
    ui=read(HERE/'bmc_ui_identity.json');replay=read(HERE/'bmc_verifier_replay.json');trust=read(HERE/'bmc_trust_probe.json')
    assert ui['inputs']['package']['decoded_sha256']==ui['inputs']['captured']['sha256']
    assert [r['return'] for r in replay['cases']]==[0,1,1,1]
    assert [r['return'] for r in trust['cases']]==[1,0,1]
    inputs=[HERE/n for n in ['download_bmc.py','inspect_bmc_image.py','extract_bmc_members.py','compare_bmc_ui.mjs',
             'elf32.py','replay_bmc_verifier.py','probe_bmc_trust.py','ExportW890Backend.java','run_ghidra.py','rea_backend.mjs',
             'bmc_download.json','bmc_filesystems.json','backend_inputs.json','bmc_ui_identity.json','bmc_verifier_replay.json','bmc_trust_probe.json',
             'rea_backend/response-001.json','rea_backend/final-close.json']]
    for run in ['comp','pdkapp','pdkapp_io','rest','manager','host']:
        directory=HERE/'ghidra_backend'/run
        info=read(directory/'analysis.json')
        binary=HERE/'backend_inputs'/info['program']
        assert info['executable_sha256']==bind(binary)['sha256']
        inputs.extend([binary,directory/'analysis.json',directory/'run.json'])
        for function in info['results']:
            assert function['completed']
            inputs.extend([directory/function['pseudocode'],directory/function['instructions']])
    bindings=[bind(p) for p in sorted(set(inputs))]
    findings=[
      {'id':'PACKAGE_IDENTITY','state':'confirmed_offline','finding':'官方2.1.11包通过已捕获华硕SHA256校验；其完整前端解压后与此前实机采集逐字节一致。',
       'limit':'没有读取实机后台共享库的哈希；同版本与前端一致不能代替后台映像实测。'},
      {'id':'VERIFIER_EXECUTION','state':'confirmed_with_explicit_models','finding':'实际PDK_VerifyBiosSignature ARM控制流通过原版、改动DXE、破坏证书、读取失败四组检查。实际选取的固件摘要与独立Python/OpenSSL原版结果一致。',
       'limit':'文件/分配/OpenSSL导入为明确模型，密码学结果由独立计算器计算；不是在BMC操作系统执行。'},
      {'id':'TRUST_BOUNDARY_CORRECTION','state':'confirmed_function_scope','finding':'仅在内存中生成的匹配测试签名链被该验证函数接受，旧签名和签后改动被拒绝。故不能把原签名失效等同于所有BMC路线必须持有华硕私钥。',
       'limit':'这不是厂商签名或设备信任授权；完整更新流程、已安装后台和启动阶段是否另有约束仍须验证。测试密钥和修改CAP均未落盘。'},
      {'id':'PREPARE_HAS_EFFECTS','state':'confirmed_static','finding':'后台Prepare调用平台切换并启用host SPI驱动；网页Prepare不是只读步骤。PDK通过BMC侧GPIO控制切换，实际写入库访问MTD设备。',
       'limit':'仅静态确认代码路径，没有切换实机SPI或调用Prepare。'},
      {'id':'WRITE_RANGE','state':'confirmed_static_call_chain','finding':'普通CAP前端发送64 MiB正文；后端按实际暂存文件长度和传入起点循环调用擦写块函数。不能称为只写48 MiB BIOS区。普通流程在写前按ASUS头描述复制保留区域到暂存文件。',
       'limit':'当前主板的MTD大小、擦除块、保留区数据和最终SPI逐字节效果未实测。'},
      {'id':'RECOVERY','state':'partially_resolved','finding':'代码中存在独立于主机UEFI服务的BMC GPIO/host-SPI/MTD写入路线；另有SD介质恢复代码，但bios_backup_image仅将预先存在的临时备份改名。',
       'limit':'未建立当前机器完整SPI备份，未验证不能POST时能否用此路线恢复。BMC设置备份/CMO仍不等于SPI备份。'},
      {'id':'BOOT_POLICY','state':'unresolved','finding':'原始FIT被保存并核对，尚无实机启动认证策略与修改区关系的完整证据。',
       'limit':'验签函数接受不等于主机可以启动。'},
    ]
    report={'generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'target':'W890E-SAGE SE 0603 / BMC public 2.1.11',
      'tool_boundary':'REA Windows P0 rejected ARM ELF; its exact failure is retained. Backend decompilation is direct Ghidra, not mislabeled REA Evidence. BIOS agents continue actual REA.',
      'findings':findings,'bindings':bindings,'hardware_actions':0,'firmware_candidates_written':0,'release_ready':False,
      'official_references':[{'url':'https://dlcdnets.asus.com/pub/ASUS/mb/LGA4710/Pro_WS_W890E-SAGE_SE/W890-ASUS-2.1.11.zip','purpose':'actual downloaded official artifact, pinned against vendor snapshot'},
        {'url':'https://www.asus.com/support/faq/1038568/','purpose':'FlashBack documented as a dedicated USB-port and physical-button operation; does not prove modified-image acceptance'}]}
    (HERE/'backend_review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'bindings':len(bindings),'release_ready':False,'report':str(HERE/'backend_review.json')}))

if __name__=='__main__': main()
