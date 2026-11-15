"""Offline, narrowly scoped FFS section-stream repair. Never writes a device.

Both pinned inputs are existing project candidates, not ASUS signed releases.
Only the final two padding bytes in the R2/P6 section streams are removed.
PE, DEPEX, Setup, and every unrelated inner FFS remain byte-identical.
"""
from pathlib import Path
import argparse, hashlib, importlib.util, json, lzma, struct, subprocess, sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.dont_write_bytecode=True
P5=ROOT/'analysis/hero_ipmi_p5'
spec=importlib.util.spec_from_file_location('p5_pack',P5/'build_candidate.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
TARGETS={'89924765-f984-4ad3-839b-51fdce378d88':'R2',
         '261135b0-7b73-49c0-bcc8-2f9cf4eef19e':'P6'}
WRAPPER='9e21fd93-9c72-4c15-8c4b-e77f1db2d792'
INPUTS={
 'observed':('analysis/hero_ipmi_p6_20261104/review-20261108/container-441b61136974/P6-RC4.CAP',
             '441b61136974278a0c6fc0d46edc159c1f1557c981ae9e4a4b42b67eb65fba0f'),
 'latest':('analysis/hero_ipmi_p6_20261104/firmware/HERO-3107-IPMI-P6-R2-RC4-UNSIGNED.CAP',
           '44256d23a952234e99bb81743bdcca28a5472a6406eceb18a82a82667b7dcff5')}

def sha(data):return hashlib.sha256(data).hexdigest()

def strict_end(blob):
    """Check actual last section end, before any alignment to a next section."""
    p=0
    while p+4<=len(blob):
        n=int.from_bytes(blob[p:p+3],'little');h=4
        if n==0xffffff:
            if p+8>len(blob):return False
            n=struct.unpack_from('<I',blob,p+4)[0];h=8
        if n<h or p+n>len(blob):return False
        end=p+n
        if end==len(blob):return True
        p=(end+3)&~3
    return False

def repair(ffs):
    body=ffs[24:]
    parts=base.sections(body)
    assert [p[0] for p in parts]==[0x13,0x10,0x15]
    fixed=base.pack_sections([p[2] for p in parts])
    assert len(body)==len(fixed)+2 and body==fixed+b'\0\0'
    assert not strict_end(body) and strict_end(fixed)
    result=base.rebuild_file(ffs,fixed)
    check=base.sections(result[24:])
    assert [(x[0],x[1]) for x in check]==[(x[0],x[1]) for x in parts]
    return result,dict(before_bytes=len(ffs),after_bytes=len(result),
                       before_ffs_sha256=sha(ffs),after_ffs_sha256=sha(result),
                       pe_sha256=sha(parts[1][1]),depex_sha256=sha(parts[0][1]),
                       removed_bytes_hex='0000')

def guided(plain,out):
    src=out/'wrapper-stream.bin';dst=out/'wrapper-stream.lzma'
    src.write_bytes(plain)
    subprocess.run([str(P5/'host-lzma/encode.exe'),str(src),str(dst)],check=True)
    z=dst.read_bytes()
    assert lzma.decompress(z,format=lzma.FORMAT_ALONE)==plain
    assert struct.unpack_from('<Q',z,5)[0]==len(plain)
    return base.make_section(2,base.LZMA_GUID+struct.pack('<HH',24,1)+z)

def main():
    p=argparse.ArgumentParser();p.add_argument('--baseline',choices=INPUTS,required=True);a=p.parse_args()
    rel,expected=INPUTS[a.baseline];original=(ROOT/rel).read_bytes();assert sha(original)==expected
    out=HERE/('candidate-'+a.baseline);out.mkdir(parents=True,exist_ok=True)
    outer=original[base.BASE:base.BASE+base.LENGTH]
    outer_files,_=base.files(outer);ob={x['guid']:x['data'] for x in outer_files}
    wrapper=ob[WRAPPER];section=base.sections(wrapper[24:]);assert len(section)==1 and section[0][0]==2
    parts=base.sections(lzma.decompress(section[0][1][20:],format=lzma.FORMAT_ALONE))
    assert len(parts)==2 and parts[1][0]==0x17
    inner=parts[1][1];files,_=base.files(inner);before={x['guid']:x['data'] for x in files}
    replacements={};changes={}
    for guid,label in TARGETS.items():
        replacements[guid],changes[label]=repair(before[guid])
        (out/(label+'-sectionfix.ffs')).write_bytes(replacements[guid])
    newinner,_=base.pack_fv(inner,replacements)
    after={x['guid']:x['data'] for x in base.files(newinner)[0]}
    assert set(after)==set(before)
    assert all(after[g]==before[g] for g in before if g not in TARGETS)
    wrapped=base.pack_sections([parts[0][2],base.make_section(0x17,newinner)])
    newwrapper=base.rebuild_file(wrapper,guided(wrapped,out))
    newouter,_=base.pack_fv(outer,{WRAPPER:newwrapper})
    oa={x['guid']:x['data'] for x in base.files(newouter)[0]}
    assert set(oa)==set(ob) and all(oa[g]==ob[g] for g in ob if g!=WRAPPER)
    cap=original[:base.BASE]+newouter+original[base.BASE+base.LENGTH:]
    assert len(cap)==len(original)==33558528
    assert cap[:base.BASE]==original[:base.BASE] and cap[base.BASE+base.LENGTH:]==original[base.BASE+base.LENGTH:]
    filename='HERO-3107-IPMI-SECTIONFIX-'+a.baseline.upper()+'-UNSIGNED.CAP'
    path=out/filename
    if path.exists():assert path.read_bytes()==cap,'Refusing to replace a different candidate'
    else:path.write_bytes(cap)
    report=dict(baseline=a.baseline,input=rel,input_sha256=expected,candidate=filename,
                candidate_sha256=sha(cap),bytes=len(cap),changed_inner_files=changes,
                unrelated_inner_ffs_byte_identical=True,unrelated_outer_ffs_byte_identical=True,
                outside_dxe_byte_identical=True,driver_code_changed=False,
                automatic_inventory_included=False,flashed=False,
                official_asus_release=False,hardware_boot_validated=False,
                scope='Only FFS trailing section padding. Does not implement automatic inventory publication.')
    (out/'build-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
