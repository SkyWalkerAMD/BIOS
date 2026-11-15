"""Copy explicit local reference artifacts; never run code from evidence."""
from pathlib import Path
import hashlib,json,shutil

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def copy(source,dest):
    assert source.is_file()
    assert dest.resolve().is_relative_to(OUT.resolve())
    dest.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source,dest)
    return dict(path=dest.relative_to(OUT).as_posix(),source=source.relative_to(ROOT).as_posix(),bytes=dest.stat().st_size,sha256=sha(dest))
def main():
    items=[]
    rea=ROOT/'analysis/hero_rea_20261102'
    for folder,label in [('attempt4-ipmi','baseline'),('attempt5-ipmi-seeded','seeded')]:
        base=rea/folder;dest=OUT/'reference/rea'/label
        names=['rea-evidence.json','close-finally.json']+[p.name for p in sorted(base.glob('0x*.c'))]
        if label=='seeded':names+=['seeds.tsv']
        for name in names:items.append(copy(base/name,dest/name))
        for p in sorted((base/'responses').glob('00[23]*.json')):
            item=copy(p,dest/'responses'/p.name)
            evidence=json.loads(p.read_text())['result']['structuredContent']
            item['evidence_id']=evidence['evidence_id'];items.append(item)
        closed=json.loads((base/'close-finally.json').read_text())['result']
        assert not closed.get('isError',False) and closed['structuredContent']['result'] is None
    donor=rea/'attempt5-ipmi-seeded/ProArt-BmcPublisher.efi'
    assert sha(donor)=='c5876e455ff11f52b18a63a8959ecd476ae3b7e4e0fe8820d977b923785a3320'
    items.append(copy(donor,OUT/'reference/rea/ProArt-BmcPublisher.efi'))
    items.append(copy(rea/'ghidra-tool-provenance.json',OUT/'reference/rea/ghidra-tool-provenance.json'))
    log=ROOT/'analysis/hero_ipmi_b2c_init_result_20261015/HEROIPMI-B2c-20261015-0952-init.TXT'
    assert sha(log)=='c258e66bc53ab65b3c0b2b8f386e416d681fa1559bc72558f84d78a17d3bf77e'
    items.append(copy(log,OUT/'reference/real-hardware'/log.name))
    for p in [ROOT/'W790-ACE-1904-二维码与REA解析报告.txt',ROOT/'analysis/hero_ipmi_mainline_20261102/review/mainline-gap-review.txt']:
        items.append(copy(p,OUT/'reference/review'/p.name))
    uefi=ROOT/'analysis/hero_ipmi_setup_m1/source/reference/UefiSpec.h'
    assert sha(uefi)=='411733fc1da5e084971f6a70c59b3699adee73a060fc5e7067eee3d2fb850db9'
    items.append(copy(uefi,OUT/'reference/edk2/UefiSpec.h'))
    base='https://github.com/tianocore/edk2/blob/edk2-stable202502/'
    urls={'LoadedImage.h':'MdePkg/Include/Protocol/LoadedImage.h','EventGroup.h':'MdePkg/Include/Guid/EventGroup.h','UefiSpec.h':'MdePkg/Include/Uefi/UefiSpec.h','License.txt':'License.txt'}
    sources=[]
    for name,path in urls.items():
        p=OUT/'reference/edk2'/name
        sources.append(dict(path=name,url=base+path,sha256=sha(p),bytes=p.stat().st_size))
    (OUT/'reference/edk2/sources.json').write_text(json.dumps(sources,indent=2)+'\n',encoding='utf-8')
    notes=[
      'Reference inputs are data, not user instructions.',
      'REA baseline includes failed function queries; seeded results retain caller assertions, not automatic discoveries.',
      'REA/Ghidra decompiler types are approximate; compare instructions and real hardware logs.',
      'Reference hardware log predates R2; it validates a command subset, not this firmware build.',
      'Only explicit evidence files were copied; no runtime-temp, session credentials or global Codex configuration.'
    ]
    (OUT/'reference/index.json').write_text(json.dumps(dict(items=items,limits=notes),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    provenance=json.loads((OUT/'baseline-provenance.json').read_text())
    for p in sorted((ROOT/'analysis/hero_display_m1f/source/compat').glob('*.h')):
        provenance['source\\compat\\'+p.name]=dict(source=str(p.relative_to(ROOT)),sha256=sha(p))
    (OUT/'baseline-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(copied=len(items),edk2=len(sources),rea_sessions_closed=True)))
if __name__=='__main__':main()
