"""Assemble P6 RC4 from pinned RC3, retaining R2 bytes and platform firmware."""
from pathlib import Path
import hashlib,importlib.util,json,lzma,struct,subprocess,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sys.dont_write_bytecode=True
P5=ROOT/'analysis/hero_ipmi_p5';RC3=ROOT/'analysis/hero_ipmi_rc3_20261104/firmware/HERO-3107-IPMI-P5-R2-RC3-UNSIGNED.CAP'
spec=importlib.util.spec_from_file_location('base_builder',P5/'build_candidate.py');base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
WRAPPER='9e21fd93-9c72-4c15-8c4b-e77f1db2d792';R2_GUID='89924765-f984-4ad3-839b-51fdce378d88'
def sha(b):return hashlib.sha256(b).hexdigest()
def guided(plain):
 folder=HERE/'compression';folder.mkdir(exist_ok=True);src=folder/(sha(plain)+'.bin');dst=src.with_suffix('.lzma');src.write_bytes(plain)
 subprocess.run([str(P5/'host-lzma/encode.exe'),str(src),str(dst)],check=True)
 z=dst.read_bytes();assert struct.unpack_from('<Q',z,5)[0]==len(plain) and lzma.decompress(z,format=lzma.FORMAT_ALONE)==plain
 return base.make_section(2,base.LZMA_GUID+struct.pack('<HH',24,1)+z)
def main():
 src=RC3.read_bytes();assert sha(src)=='8ffc4b33f6d0e2bb7180c724de01a805f556ad126d08830e7f052b37ce771951'
 outer=src[base.BASE:base.BASE+base.LENGTH];outerfiles,_=base.files(outer)
 wrapper=next(x['data'] for x in outerfiles if x['guid']==WRAPPER)
 sec=base.sections(wrapper[24:]);assert len(sec)==1 and sec[0][0]==2
 inners=base.sections(lzma.decompress(sec[0][1][20:],format=lzma.FORMAT_ALONE));assert len(inners)==2 and inners[1][0]==0x17
 inner=inners[1][1];old,_=base.files(inner);oldby={x['guid']:x['data'] for x in old}
 setup_parts=base.sections(oldby[base.SETUP][24:]);assert [s[0] for s in setup_parts]==[0x13,2,0x14]
 setup=base.rebuild_file(oldby[base.SETUP],base.pack_sections([setup_parts[0][2],guided(base.make_section(0x10,(HERE/'native/Setup-P6-RESOURCE-REVIEW.efi').read_bytes())),setup_parts[2][2]]))
 spf_parts=base.sections(oldby[base.SPF][24:]);spf_sub=base.sections(lzma.decompress(spf_parts[0][1][20:],format=lzma.FORMAT_ALONE))
 assert [s[0] for s in spf_sub]==[0x18,0x15] and spf_sub[0][1][:16]==uuid.UUID(base.SPF).bytes_le
 spf=base.rebuild_file(oldby[base.SPF],guided(base.pack_sections([base.make_section(0x18,spf_sub[0][1][:16]+(HERE/'native/AMITSESetupData-P6.bin').read_bytes()),spf_sub[1][2]])))
 driver=(HERE/'HeroIpmiNativeP6.ffs').read_bytes();assert str(uuid.UUID(bytes_le=driver[:16]))==base.DRIVER
 newinner,ii=base.pack_fv(inner,{base.SETUP:setup,base.SPF:spf,base.DRIVER:driver})
 newfiles,_=base.files(newinner);assert next(x['data'] for x in newfiles if x['guid']==R2_GUID)==oldby[R2_GUID]
 replacement=base.rebuild_file(wrapper,guided(base.pack_sections([inners[0][2],base.make_section(0x17,newinner)])))
 newouter,oi=base.pack_fv(outer,{WRAPPER:replacement});result=src[:base.BASE]+newouter+src[base.BASE+base.LENGTH:]
 assert len(result)==len(src)==33558528 and result[:base.BASE]==src[:base.BASE] and result[base.BASE+base.LENGTH:]==src[base.BASE+base.LENGTH:]
 folder=HERE/'firmware';folder.mkdir(exist_ok=True);cap=folder/'HERO-3107-IPMI-P6-R2-RC4-UNSIGNED.CAP';cap.write_bytes(result)
 report=dict(version='HERO 3107 IPMI P6 + R2 RC4',candidate=str(cap.relative_to(ROOT)),candidate_bytes=len(result),candidate_sha256=sha(result),base_sha256=sha(src),changes=[base.SETUP,base.SPF,base.DRIVER,WRAPPER],r2_ffs_sha256=sha(oldby[R2_GUID]),outside_dxe_byte_identical=True,inner=ii,outer=oi,official_asus_release=False,hardware_validated=False)
 (HERE/'candidate-build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('inner','outer')},indent=2))
if __name__=='__main__':main()
