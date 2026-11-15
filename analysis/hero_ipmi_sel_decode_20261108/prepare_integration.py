"""Create an isolated source patch and link-only EFI preview. No hardware access."""
from pathlib import Path
import difflib,hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
BASE=ROOT/'analysis/hero_ipmi_p6_20261104';PREVIEW=HERE/'integration-preview'
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def diff(old,new,name):
    return ''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),
        fromfile='a/'+name if old else '/dev/null',tofile='b/'+name))

def main():
    PREVIEW.mkdir(exist_ok=True);(PREVIEW/'source').mkdir(exist_ok=True)
    meta=json.loads((BASE/'runtime-build.json').read_text())
    for path,digest in meta['sources'].items():assert sha(BASE/path)==digest,path
    original=(BASE/'source/transport.c').read_text()
    start=original.index('  /* Preserve every byte. OEM entries must not be decoded as standard events. */')
    end=original.index('  text[pos]=0;value_text(V_SEL0+shown,text);',start)
    end+=len('  text[pos]=0;value_text(V_SEL0+shown,text);')
    updated=original[:start]+'''  /* Decode only standard semantics; keep all 16 raw bytes and the fixed ABI. */
  char text[sizeof(values[0])];
  sel_format_record(text,sizeof(text),rx+5,16);
  value_text(V_SEL0+shown,text);'''+original[end:]
    assert original.count('#include "p1.h"')==1
    updated=updated.replace('#include "p1.h"','#include "p1.h"\n#include "sel_decode.h"')
    (PREVIEW/'source/transport.c').write_text(updated,encoding='ascii',newline='\n')
    oldbuild=(BASE/'build_runtime.py').read_text()
    assert oldbuild.count("'presentation','publisher','transport'")==1
    newbuild=oldbuild.replace("'presentation','publisher','transport'","'presentation','publisher','sel_decode','transport'")
    (PREVIEW/'build_runtime.py').write_text(newbuild,encoding='ascii',newline='\n')
    patch=diff(original,updated,'source/transport.c')+diff(oldbuild,newbuild,'build_runtime.py')
    for name in ['sel_decode.c','sel_decode.h']:
        source=(HERE/name).read_text()
        (PREVIEW/'source'/name).write_text(source,encoding='ascii',newline='\n')
        patch+=diff('',source,'source/'+name)
    (HERE/'integration.patch').write_text(patch,encoding='ascii',newline='\n')
    # Compile transport against actual P6 headers. Link with the unmodified
    # reviewed P6 objects to detect ABI/symbol/import regressions. Never write BASE.
    prior=next(cmd for cmd in meta['commands'] if any(s.endswith('transport.c') for s in cmd))
    zig=prior[0];flags=prior[2:prior.index('-c')]+['-I',str(BASE/'source'),'-I',str(PREVIEW/'source')]
    env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(HERE/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(HERE/'zig-local')
    commands=[]
    (PREVIEW/'abi_check.c').write_text('#include "p1.h"\n_Static_assert(V_COUNT==41,"String ABI changed");\n_Static_assert(sizeof(values[0])==160,"Value capacity changed");\n_Static_assert(V_CONFIG_STATUS-V_SEL0==16,"SEL record count changed");\n',encoding='ascii')
    for name,source in [('transport',PREVIEW/'source/transport.c'),('sel_decode',PREVIEW/'source/sel_decode.c'),('abi_check',PREVIEW/'abi_check.c')]:
        cmd=[zig,'clang',*flags,'-c',str(source),'-o',str(PREVIEW/(name+'.obj'))]
        subprocess.run(cmd,env=env,cwd=ROOT,check=True);commands.append(cmd)
    names=['common','probe_core','command_policy','presentation','publisher','settings','driver','p6_backend']
    objects=[BASE/(name+'.obj') for name in names]
    object_hashes={str(p.relative_to(ROOT)):sha(p) for p in objects}
    out=PREVIEW/'HeroIpmiP6SelPreview.efi'
    cmd=[zig,'lld-link','/subsystem:efi_boot_service_driver','/entry:efi_main','/nodefaultlib','/machine:x64',
        '/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0',
        '/map:'+str(PREVIEW/'driver.map'),'/out:'+str(out)]+[str(p) for p in objects]+[str(PREVIEW/(n+'.obj')) for n in ['transport','sel_decode']]
    subprocess.run(cmd,env=env,cwd=ROOT,check=True);commands.append(cmd)
    pe=pefile.PE(str(out));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();out.write_bytes(pe.write());pe=pefile.PE(str(out))
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==11 and pe.verify_checksum()
    assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
    assert 'sel_format_record' in (PREVIEW/'driver.map').read_text()
    for path,digest in meta['sources'].items():assert sha(BASE/path)==digest,path
    for path,digest in object_hashes.items():assert sha(ROOT/path)==digest,path
    refs=json.loads((ROOT/'analysis/hero_ipmi_p1/reference/standards-sources.json').read_text())['IpmiNetFnStorage.h']
    ref_path=ROOT/'analysis/hero_ipmi_p1/reference/IpmiNetFnStorage.h';assert sha(ref_path)==refs['sha256']
    wheel=ROOT/'tools/hero-ipmi-readonly/wheels/pyghmi-1.6.19-py3-none-any.whl'
    assert sha(wheel)=='4d35ab89bf0217705a2deaea3335454ac56e43f369eeae663e78cb0b0082a1df'
    dependencies=['tools/hero-ipmi-readonly/site/pyghmi/ipmi/events.py','tools/hero-ipmi-readonly/site/pyghmi/ipmi/private/constants.py',
        'analysis/hero_ipmi_p5_field_20261104/transactions.json','analysis/hero_ipmi_p6_20261104/source/p1.h',
        'analysis/hero_ipmi_p6_20261104/source/transport.c','analysis/hero_ipmi_p6_20261104/build_runtime.py']
    provenance={'field_layout':{'path':str(ref_path.relative_to(ROOT)),**refs,'lines':'528-554, 733-747'},
        'event_reference':{'package':'pyghmi 1.6.19','wheel_sha256':sha(wheel),
        'notes':'Source consulted for event tables, low-nibble offset, direction and timestamp boundary; no dependency at runtime.',
        'lines':{'events.py':'303-380, 409-465, 499-517','constants.py':'35-80, generic_type_offsets, sensor_type_offsets'}},
        'local_sources':{p:sha(ROOT/p) for p in dependencies},
        'new_network_operations':False,'bmc_operations':False}
    (HERE/'source-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    report={'scope':'Offline link-only P6 EFI preview. Not a CAP, not flashed, not dynamically loaded, no new hardware validation.',
        'baseline_driver_sha256':meta['driver_sha256'],'baseline_sources_unchanged':True,'original_object_hashes':object_hashes,
        'driver_sha256':sha(out),'driver_bytes':out.stat().st_size,'patch_sha256':sha(HERE/'integration.patch'),
        'native_forms_unchanged':sha(BASE/'native/Setup-forms-P6.bin')==meta['native_forms_sha256'],
        'string_abi_count':41,'string_capacity':160,'sel_display_records':16,'pe_checksum_valid':True,'imports':[],
        'commands':commands}
    (HERE/'integration-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ['commands','original_object_hashes']},indent=2))
if __name__=='__main__':main()
