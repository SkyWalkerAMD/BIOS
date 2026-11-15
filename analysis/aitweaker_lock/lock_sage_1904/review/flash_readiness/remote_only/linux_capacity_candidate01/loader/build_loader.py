"""Build a deterministic, contract-pinned UEFI bootstrap. Never executes EFI here."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys
OUT=Path(__file__).resolve().parent
ROOT=next(p for p in OUT.parents if (p/'tools/zig-x86_64-windows-0.14.1/zig.exe').is_file())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def build(contract_path,build_dir=None):
    contract=json.loads(Path(contract_path).read_text(encoding='utf8'))
    dest=(Path(build_dir) if build_dir else OUT/'build').resolve();assert dest.is_relative_to(OUT)
    dest.mkdir(parents=True,exist_ok=True)
    cmdline=contract['cmdline'];assert isinstance(cmdline,str) and cmdline.isascii() and 0<len(cmdline)<2048 and all(32<=ord(c)<127 for c in cmdline)
    assert 'initrd=' not in cmdline and 'dtb=' not in cmdline
    arrays=[]
    for label in ['kernel','initrd']:
        p=Path(contract[label]['path']).resolve();assert p.is_relative_to(OUT.parent)
        assert p.stat().st_size==contract[label]['bytes'] and sha(p)==contract[label]['sha256']
        assert 0<p.stat().st_size<=64*1024*1024
        if label=='kernel':assert p.read_bytes()[:2]==b'MZ'
        if label=='initrd':assert p.name!='initramfs-lts','stock Alpine initramfs is forbidden'
        arrays.append(f'#define LC_{label.upper()}_BYTES {p.stat().st_size}ULL\nstatic const uint8_t lc_{label}_sha[32]={{'+','.join('0x'+contract[label]['sha256'][i:i+2] for i in range(0,64,2))+'};\n')
    header='/* Generated from fixed payload contract; no media-provided commands. */\n'+''.join(arrays)+'#define LC_CMDLINE L'+json.dumps(cmdline)+'\n#define LC_CMDLINE_ASCII '+json.dumps(cmdline)+'\n'
    (dest/'payload_contract.h').write_text(header,encoding='ascii')
    zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(OUT/'cache/global');env['ZIG_LOCAL_CACHE_DIR']=str(OUT/'cache/local')
    cc=[str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),'-I',str(OUT/'source'),'-I',str(dest),'-std=c11','-Oz','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
    for name in ['bootstrap','sha256']:subprocess.run(cc+['-c',str(OUT/'source'/f'{name}.c'),'-o',str(dest/f'{name}.obj')],env=env,check=True)
    binary=dest/'BOOTX64.EFI'
    subprocess.run([str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/opt:ref','/map:'+str(dest/'BOOTX64.map'),'/out:'+str(binary),str(dest/'bootstrap.obj'),str(dest/'sha256.obj')],env=env,check=True)
    pe=pefile.PE(str(binary));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();binary.write_bytes(pe.write())
    assert pe.OPTIONAL_HEADER.Subsystem==10 and pe.FILE_HEADER.Machine==0x8664 and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size
    report={'artifact_type':'fixed payload EFI bootstrap','scope':'Local build only; not hardware authorization','contract_status':contract.get('status','UNAPPROVED'),'contract':contract,'contract_file_sha256':sha(contract_path),'cmdline_ascii_sha256':hashlib.sha256(cmdline.encode('ascii')).hexdigest(),'cmdline_utf16le_with_nul_sha256':hashlib.sha256((cmdline+'\0').encode('utf-16-le')).hexdigest(),'binary':str(binary),'binary_bytes':binary.stat().st_size,'binary_sha256':sha(binary),'sources':{str(p.relative_to(OUT)):sha(p) for p in sorted((OUT/'source').glob('*')) if p.is_file()},'compiled_sources':['source/bootstrap.c','source/sha256.c'],'generated_header_sha256':sha(dest/'payload_contract.h'),'toolchain_sha256':sha(zig),'subsystem':10,'machine':'x86_64','imports':0,'relocation_bytes':pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size,'loader_file_reads':['\\LINUX\\VMLINUX.EFI','\\LINUX\\CAPACITY01.IMG'],'require_boot_volume_readonly':False,'readonly_metadata_policy':'Log only; hash-verified RAM payloads never reopened and no write methods are called','random_seed_gate':'Two size-only GetVariable calls, exact EFI_NOT_FOUND with zero size required, never retrieve seed contents','initrd_delivery':'LoadFile2 on Linux vendor media device path, from previously hashed RAM','kernel_delivery':'LoadImage SourceBuffer from previously hashed RAM; fixed same-device DevicePath','on_any_error':'Visible nonreturning bounded Stall loop; no fallback OS, reset, or Exit call','loader_persistent_writes':[]}
    (dest/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf8');return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('contract',type=Path);p.add_argument('--build-dir',type=Path);a=p.parse_args();print(json.dumps(build(a.contract,a.build_dir),indent=2))
