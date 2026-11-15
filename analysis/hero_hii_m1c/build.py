"""Build standalone M1c HII diagnostic; use original static form bytes."""
from pathlib import Path
import sys,re,hashlib,subprocess,json,os
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    old=(OUT.parent/'hero_ipmi_setup_m1a/source/forms.h').read_text()
    source='/* Exact M1a static form/package bytes; HII-only test, no IPMI engine. */\n'
    source+=re.search(r'static GUID minimal_guid=.*?;',old).group(0)+'\n'
    source+=re.search(r'static const uint8_t minimal_packages\[\]=\{.*?\};',old,re.S).group(0)+'\n'
    (OUT/'source/minimal.h').write_text(source)
    payload=bytes(int(x,16) for x in re.findall(r'0x([0-9a-f]{2})(?:,|\s)',source.split('minimal_packages')[1]))
    assert payload==(OUT.parent/'hero_ipmi_setup_m1a/HERO-M1A-MINIMAL-HII.bin').read_bytes()
    marker=b'HERO-HII-M1C\r\n';assert len(marker)==14
    (OUT/'USB/HERO-IPMI-M1C.TAG').write_bytes(marker)
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
    obj=OUT/'diag.obj';dest=OUT/'USB/EFI/BOOT/BOOTX64.EFI'
    flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
    commands=[[str(ZIG),'clang',*flags,'-c',str(OUT/'source/diag.c'),'-o',str(obj)],
              [str(ZIG),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(OUT/'diag.map'),'/out:'+str(dest),str(obj)]]
    for cmd in commands:subprocess.run(cmd,check=True,cwd=ROOT,env=env)
    pe=pefile.PE(str(dest));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();dest.write_bytes(pe.write());pe=pefile.PE(str(dest))
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10 and pe.verify_checksum()
    assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
    analyzer=subprocess.run([str(ZIG),'clang',*flags,'--analyze','-Xanalyzer','-analyzer-output=text',str(OUT/'source/diag.c')],capture_output=True,text=True,cwd=ROOT,env=env,check=True)
    assert not analyzer.stdout and not analyzer.stderr,(analyzer.stdout,analyzer.stderr)
    report=dict(version='M1c',image_sha256=sha(dest),bytes=dest.stat().st_size,form_package_sha256=hashlib.sha256(payload).hexdigest(),original_form_bytes_preserved=True,static_analysis='no diagnostics',commands=commands,sources={p.name:sha(p) for p in (OUT/'source').iterdir() if p.is_file()})
    (OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('commands','sources')},indent=2))
if __name__=='__main__':main()
