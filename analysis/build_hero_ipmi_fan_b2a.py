"""Build the standalone USB UEFI probe; never installs or runs it on hardware."""
from pathlib import Path
import hashlib, json, os, subprocess, sys
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/hero_ipmi_fan_b2a'
SRC=OUT/'source'
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile

def build():
    boot=OUT/'USB/EFI/BOOT'
    boot.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global')
    env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
    # Invoke Zig's bundled Clang/LLD directly; no Windows SDK or subprocess
    # compiler discovery is needed for this freestanding EFI image.
    commands=[]
    for name in ('probe','probe_core'):
        args=[str(ZIG),'clang','-target','x86_64-unknown-windows-msvc',
              '-nostdinc','-isystem',str(ZIG.parent/'lib/include'),
              '-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding',
              '-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar',
              '-c',str(SRC/(name+'.c')),'-o',str(OUT/(name+'.obj'))]
        subprocess.run(args,check=True,env=env,cwd=ROOT)
        commands.append(args)
    args=[str(ZIG),'lld-link','/subsystem:efi_application','/entry:efi_main',
          '/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat',
          '/timestamp:0','/map:'+str(OUT/'probe.map'),
          '/out:'+str(boot/'BOOTX64.EFI'),str(OUT/'probe.obj'),str(OUT/'probe_core.obj')]
    subprocess.run(args,check=True,env=env,cwd=ROOT)
    commands.append(args)
    exe=boot/'BOOTX64.EFI'
    pe=pefile.PE(str(exe))
    pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum()
    exe.write_bytes(pe.write())
    pe=pefile.PE(str(exe))
    assert pe.FILE_HEADER.Machine==0x8664
    assert pe.OPTIONAL_HEADER.Subsystem==10
    assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size>0
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0
    assert pe.verify_checksum()
    (OUT/'USB/HERO-PROBE-USB.TAG').write_bytes(b'HERO-IPMI-FAN--B2a\r\n')
    report=dict(status='BUILT_NOT_TESTED_ON_TARGET',purpose='B2a: distinguish first-status FF from PCI API error; optional S status-only sampling; retains B2 experiments.',
                status_diagnostic={'trigger':'S, offered only after very first KCS status returns FF with successful PCI API read and zero KCS writes/data reads',
                    'samples_max':31,'spacing_seconds':1,'operations':['read same PCI function config','read BAR1+E8C KCS status'],
                    'forbidden':['KCS data read','KCS write','automatic request retry','reset or bridge reconfiguration'],
                    'stop_conditions':['config/card/BAR changed','PCI read failure','log failure','stall failure']},
                target_board='ROG MAXIMUS Z790 HERO',target_bios_versions=['3001','3107'],
                oem_mode_bios_versions=['3107'],
                oem_warning='Changes BMC state. Persistence, full effects and rollback are unverified; PCI cleanup does not undo these commands.',
                oem_fingerprint='1C 01 00 20 81 01 03 02 BF 3F 0A 00 93 10 0D 00 00 00',
                oem_sequence=json.loads((ROOT/'analysis/hero_sensor_r1/verification.json').read_text())['mock_x64_cases'][0]['commands'],
                fan_experiment={'trigger':'F only; complete initialized baseline, exact HERO 3107/BMC identity, no resident IPMI transport, working log',
                    'steps':14,'writes':['30/9A 01 01 <15-byte original RPM map with ONLY index 2 changed from 00 to 62>', '30/94 20 01'],
                    'gets':['30/9A 00 00','30/9A 01 00','30/9A 02 00','30/9A 03 00'],
                    'preconditions':'Mode 0; original RPM index 2 is 0; exact reply lengths',
                    'verification':'RPM setter echo and GET agree; mode/PWM/type unchanged before and after scan enable',
                    'hardware_status':'NOT TESTED ON TARGET; register 62 is a candidate, not a proven HERO source',
                    'excluded':['mode/PWM/type setters','host EC I/O','loading DXE drivers','BIOS/BMC image flashing'],
                    'rollback':'No automatic rollback; Q only restores the temporary PCI memory-enable bit'},
                real_baseline_sha256=hashlib.sha256((OUT/'evidence/HEROIPMI-000(1).TXT').read_bytes()).hexdigest(),
                optional_pci_change={'trigger':'E key plus valid card/BAR and working log',
                    'offset':4,'width_bits':16,'changed_bit':1,'bus_master_enable':False,
                    'restore':'Attempt on normal and handled-error paths; verify by reading Command. Hangs/power loss cannot run cleanup.'},
                protocol_label_correction={'A1_incorrect_PCI_enumeration_GUID':'72338391-FB43-44A1-A9A2-64FEE1FC5E41',
                    'standard_PI_PCI_enumeration_GUID':'30CFE3E7-3DE1-4586-BE20-DEABA1B3B793'},
                image='USB/EFI/BOOT/BOOTX64.EFI',sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
                bytes=exe.stat().st_size,machine='x64',subsystem=10,
                no_imports=True,relocations_present=True,checksum_valid=True,unsigned=True,
                source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in SRC.glob('*') if p.is_file()},
                compiler='Zig 0.14.1 portable; clang C frontend, LLVM linker',
                commands=commands)
    (OUT/'build.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['image','sha256','bytes','subsystem','unsigned']},indent=2))

if __name__=='__main__': build()
