"""Prepare only the byte-identical ASUS 3107 control for a physical FlashBack test."""
from pathlib import Path
import json,hashlib,zipfile
P=Path(__file__).resolve().parent
ROOT=P.parents[1]
source=ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
data=source.read_bytes()
digest=hashlib.sha256(data).hexdigest()
assert digest=='e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
out=P/'official-control'
out.mkdir(exist_ok=True)
(out/'MZ790H.CAP').write_bytes(data)
instructions='''第一步：官方 HERO 3107 FlashBack 对照，不含修改版。
CAP SHA256: e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a
CAP大小: 33558528字节。
1. 将 MZ790H.CAP 复制到 FAT32/MBR 单分区 U 盘根目录。
2. 主机保持关机，保留电源供电。插入背板标有 BIOS FlashBack 的专用 USB 接口。
3. 按 FlashBack 按钮约3秒，直到指示灯闪烁；处理期间不拔盘、不断电、不开机、不按清 CMOS。
4. 记录指示灯持续时间及最终状态。若很快常亮，报告失败；不要当作完成。
5. 等指示灯熄灭后报告结果，由远程继续开机核对。若仍在闪烁，继续等待，不打断。
这一步会实际重写官方3107，可能重置BIOS设置。它验证当前板的官方恢复盘通道，不能证明修改版被接受，也不能证明所有损坏都能恢复。
官方步骤: https://www.asus.com/support/faq/1038568/
'''.encode('utf-8')
(out/'第一步-官方对照说明.txt').write_bytes(instructions)
manifest=dict(date='2026-11-04',version='ASUS official 3107 control, NOT IPMI modified firmware',
              bytes=len(data),sha256=digest,ez_flash_accepted_for_confirmation=True,
              flashback_acceptance_verified=False,physical_test_pending=True)
(out/'identity.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
dest=ROOT/'analysis/HERO-3107-OFFICIAL-FLASHBACK-CONTROL.zip'
with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for f in sorted(out.iterdir()):z.write(f,f.name)
with zipfile.ZipFile(dest) as z:
    assert z.testzip() is None and hashlib.sha256(z.read('MZ790H.CAP')).hexdigest()==digest
print(json.dumps(dict(package=str(dest),bytes=dest.stat().st_size,sha256=hashlib.sha256(dest.read_bytes()).hexdigest()),indent=2))
