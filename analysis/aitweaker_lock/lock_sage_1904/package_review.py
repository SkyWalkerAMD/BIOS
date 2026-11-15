"""Create a source/evidence archive; deliberately exclude firmware updater tools."""
from pathlib import Path
import datetime, hashlib, json, zipfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf8'))

def main():
    delivery=read(HERE/'bios_delivery.json')
    assert sha(Path(delivery['capsule']))==delivery['capsule_sha256']
    assert sha(HERE/'driver/build/AiTweakerLock1904.efi')==delivery['driver_sha256']
    paths=set()
    for folder in ['core','driver','lab','navigation','analysis']:
        for p in (HERE/folder).glob('*'):
            if p.is_file() and p.suffix in {'.c','.h','.py','.json','.mjs','.tsv'}:paths.add(p)
    for p in HERE.glob('*'):
        if p.is_file() and p.suffix in {'.py','.json'} and p.name!='review_delivery.json':paths.add(p)
    for folder,patterns in {
        'driver/build':['*.efi','*.EFI','*.json','driver.map'],
        'analysis/modules':['*.efi','*.json','*.txt'],
        'navigation/rea':['*.json','*.txt'],
        'lab/asus_review':['*.json'],
        'remote_172_20_2_162':['identity*.json'],
    }.items():
        for pattern in patterns:paths.update(p for p in (HERE/folder).glob(pattern) if p.is_file())
    for p in (HERE/'driver/vm_runs').rglob('*'):
        if p.is_file() and p.suffix in {'.json','.log'}:paths.add(p)
    external={ROOT/name:digest for name,digest in read(HERE/'driver/build/build.json')['external_sources'].items()}
    for path,digest in external.items():assert sha(path)==digest
    manifest={'target':'Pro WS W790E-SAGE SE / 1904 / EXP01','generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope':'Source, binary identity and offline evidence. No hardware password test or firmware flash performed.',
              'driver_sha256':delivery['driver_sha256'],'capsule_sha256':delivery['capsule_sha256'],
              'original_capsule_sha256':'aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3',
              'files':{p.relative_to(HERE).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(paths)}}
    for path,digest in external.items():manifest['files']['external/'+path.name]={'bytes':path.stat().st_size,'sha256':digest,'workspace_path':str(path.relative_to(ROOT))}
    archive=ROOT/'W790E-SAGE-SE-1904-AiTweaker-源码与验证-EXP01.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for p in sorted(paths):z.write(p,p.relative_to(HERE).as_posix())
        for path in external:z.write(path,'external/'+path.name)
        z.writestr('REVIEW-MANIFEST.json',json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
        z.writestr('说明.txt','SAGE SE 1904 源码与离线证据归档。不是启动盘或刷写包。\n构建使用工作区已有 Zig、UEFIExtract、Python依赖、REA/Ghidra、QEMU；原版 CAP 按 analysis/original_identity.json 下载及校验。\nBIOS 实验映像另见 W790E-SAGE-SE-1904-AiTweaker密码BIOS-EXP01.zip。\n')
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for name,item in manifest['files'].items():assert hashlib.sha256(z.read(name)).hexdigest()==item['sha256']
    result={'status':'ARCHIVE_VERIFIED','archive':str(archive),'bytes':archive.stat().st_size,'sha256':sha(archive),'verified_files':len(manifest['files'])}
    (HERE/'review_delivery.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
