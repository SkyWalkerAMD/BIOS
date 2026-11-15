"""Bind a read-only P6 source snapshot to the independently recovered donor behavior."""
from pathlib import Path
import hashlib,json
P=Path(__file__).resolve().parent;BASE=P.parent
names=['source/settings.c','source/driver.c','source/settings.h','backend/p6_backend.c','native/build_native_p6.py']
snap=P/'p6-source-snapshot';snap.mkdir(exist_ok=True)
bindings=[];texts={}
for name in names:
 src=BASE/name;data=src.read_bytes();out=snap/Path(name).name;out.write_bytes(data)
 texts[name]=data.decode('utf-8').splitlines()
 bindings.append({'source':str(src),'snapshot':str(out.relative_to(P)),'sha256':hashlib.sha256(data).hexdigest()})
def lines(file,needle):
 return {'file':str(BASE/file),'lines':[i for i,l in enumerate(texts[file],1) if needle in l]}
report={
 'scope':'Read-only lifecycle/source comparison against independent Creator analysis; not a new machine-code test run or hardware validation.',
 'bindings':bindings,
 'findings':[
 {'severity':'observed','topic':'Private configuration',
 'detail':'P6 uses private HeroIpmiSettings GUID BEF09FE1-8540-4BE1-9082-E6624328F435, 32-byte schema, rather than writing Creator ServerSetup615B. Defaults disable WDT, preserve LAN and BMC global logging, and disable erase/full policies.',
 'evidence':[lines('source/settings.h','P6_CFG_GUID'),lines('source/settings.c','static void defaults')]},
 {'severity':'observed','topic':'Boot lifecycle',
 'detail':'ReadyToBoot calls p6_apply_settings; BeforeBoot calls p6_start_os_watchdog, which applies settings first if ReadyToBoot has not yet done so. Apply prepares but does not start the watchdog; SetupEnter and both Shell GUIDs call the stop helper. The GUID bytes match the independently recovered Creator and HERO markers.',
 'evidence':[lines('source/driver.c','static GUID before_guid'),lines('source/driver.c','static GUID shell_guid'),lines('source/driver.c','p6_apply_settings();'),lines('source/driver.c','p6_start_os_watchdog();'),lines('source/driver.c','p6_stop_os_watchdog();')]},
 {'severity':'observed','topic':'Callback serialization and repeats',
 'detail':'All driver event callbacks are registered at TPL8 and guarded by local busy. p6_apply_settings has one-boot and failure latches. Repeated BeforeBoot does not reset an already started timer; stop clears prepared/started so a later boot attempt can prepare/start again. Creator arms on each eligible BeforeBoot callback, so repeated attempts are not identical. This local guard does not independently prove mutual exclusion against other firmware drivers.',
 'evidence':[lines('source/driver.c','create_event('),lines('source/driver.c','create_event_ex('),lines('source/settings.c','if(settings_busy||applied_this_boot'),lines('source/settings.c','||started)return;'),lines('source/settings.c','prepared=started=0;')]},
 {'severity':'documented limitation','topic':'UEFI applications and ownership',
 'detail':'Native help correctly says OS or another UEFI application may arm the watchdog. Backend watchdog_owned excludes a running non-OSLoad timer, but TimerUse3 alone cannot prove exclusive P6 authorship. Setup/Shell stop is guarded by persisted state.applied.wdt_enabled, not a cryptographic/exclusive creator identity. Avoid claiming that another software owner using the same OSLoad use3 can be reliably distinguished.',
 'evidence':[lines('native/build_native_p6.py','another UEFI application'),lines('backend/p6_backend.c','static int watchdog_owned'),lines('source/settings.c','!state.applied.wdt_enabled')]},
 {'severity':'intentional difference','topic':'BMC global logging versus Creator Components',
 'detail':'P6 exposes BMC System event logging and controls06/2E global bit3; it does not implement Creator PEI RSC status-code logging or the59-entry mapping. Native help labels this difference explicitly. Therefore Creator SEL Components and early PEI POST/error coverage remain unimplemented in this snapshot.',
 'evidence':[lines('native/build_native_p6.py','BMC System event logging'),lines('native/build_native_p6.py','Creator SEL Components'),lines('source/settings.c','p6_sel_logging(')]},
 {'severity':'intentional difference','topic':'When full policy',
 'detail':'P6 applies the selected policy once during boot settings application only if GetSELInfo free_bytes<16. Creator checks historical overflow bit7 in its relevant producer paths, including each mapped PEI event. P6 intentionally does not delete merely because overflow remains set after space is available; it is neither the Creator per-event policy nor an ongoing BMC runtime full-log policy. Unknown/saturated free-space values do not trigger this <16 test.',
 'evidence':[lines('source/settings.c','inf.free_bytes<16'),lines('source/settings.c','if(boot_config.sel_full)'),lines('native/build_native_p6.py','When SEL is full at boot')]},
 {'severity':'intentional difference','topic':'Erase and retry',
 'detail':'P6 consumes a one-shot erase request before starting the BMC operation and blocks ambiguous failures in persistent journal. Creator consumes next-reset after attempting clear even if it failed. In P6 an explicit Retry alone does not resurrect an already consumed one-shot erase; reselecting Erase once is needed if the operator intends a fresh destructive attempt. Repeated-boot erase remains a boot action; no host POST logging gate exists.',
 'evidence':[lines('source/settings.c','unsigned retry=boot_config.retry,erase_once='),lines('source/settings.c','next.sel_erase=0;'),lines('source/settings.c','replay a one-shot erase'),lines('native/build_native_p6.py','Next boot once is consumed')]},
 {'severity':'intentional difference','topic':'Network channel and pending state',
 'detail':'P6 auto mode requires exactly one discovered Ethernet channel; Creator uses the first cached/discovered LAN channel. P6 persists selected source and compares against successful applied state, applying on changed settings or explicit Retry, whereas Creator resets source toUnspecified before applying. P6 changes only source/IP/mask/gateway; Creator also writes gateway MAC parameter13. P6 leaves gateway MAC unmodified and does not claim two-channel automatic equivalence.',
 'evidence':[lines('backend/p6_backend.c','if(count!=1)'),lines('backend/p6_backend.c','static int lan_write_state'),lines('source/settings.c','boot_config.source!=state.applied.source'),lines('native/build_native_p6.py','Applied when saved settings change')]},
 {'severity':'intentional difference','topic':'LAN transactions and command validation',
 'detail':'P6 uses SetInProgress acquire/commit/complete and exact readback, with bounded recovery, unlike the recovered Creator routine which merely waits for SetInProgress clear before individual writes. P6 treats optional commit rejection and unknown source as bounded failures rather than silently claiming Creator-equivalent network support. Real card support must be verified.',
 'evidence':[lines('backend/p6_backend.c','P6_STAGE_ACQUIRE'),lines('backend/p6_backend.c','P6_STAGE_COMMIT'),lines('backend/p6_backend.c','return lan_verify(')]}
 ],
 'conclusion':'The P6 lifecycle is consistent with the intended BeforeBoot/Setup/Shell design and explicitly labels major semantic differences. No newly proven source-level blocker was identified in this focused comparison. This is not a full concurrency or backend correctness audit.',
 'pending':'Independent final CAP container/identity/checksum review awaits parent-provided completed build. Hardware acceptance of writes is not established by source review.'}
(P/'p6-lifecycle-differences.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
path=P/'creator-behavior-review.json';creator=json.loads(path.read_text(encoding='utf-8'))
creator['p6_implementation_comparison']={'file':'p6-lifecycle-differences.json','bindings':bindings,'findings':report['findings'],'conclusion':report['conclusion']}
path.write_text(json.dumps(creator,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
with (P/'creator-behavior-review.txt').open('a',encoding='utf-8') as f:
 f.write('''\nP6 当前源码差异（只读快照，详见p6-lifecycle-differences.json）：
- 私有32B变量，非Creator615B布局。ReadyToBoot应用/准备；BeforeBoot启动；Setup/Shell停止。重复BeforeBoot不会重置正在计时的WDT。
- BMC System event logging是全局bit3，尚未包含Creator59项映射/PEI POST日志。标签已明确区分。
- When SEL is full at boot仅每次启动应用检查free_bytes<16；有意不因历史overflow位仍置位而继续删除。没有Creator逐PEI事件执行或常驻BMC策略。
- Next boot erase在发送前消费；失败后的Retry不会恢复已消费的清除请求，需要重新选择Erase once才是一次新的清除意图。
- 网络auto要求唯一Ethernet通道；保留source并用成功状态判断变更，非Creator写前清0。只设置source/IP/mask/gateway，保留gateway MAC。
- WDT所谓owned目前指OSLoad用途与启用状态匹配，不能唯一辨认其他软件创建的相同TimerUse3计时器。
本次聚焦生命周期对照未新增确定阻断项；尚待最终CAP独立复核与实机功能验收。
''')
print(json.dumps({'file':str(P/'p6-lifecycle-differences.json'),'findings':len(report['findings']),'sources':bindings},indent=2))
