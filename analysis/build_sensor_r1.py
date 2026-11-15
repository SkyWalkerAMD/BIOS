"""Offline, experimental HERO 3001 sensor bootstrap; NEVER flashes hardware.

Reuses three reviewed donor DXE images, changes only local copies, and appends
their FFS files in an existing HERO firmware volume's erased tail. No original
FFS, firmware volume boundary, capsule header, PEI, ME or NVRAM data is moved.
This is a static experiment, not an ASUS-signed or hardware-qualified update.
"""
from pathlib import Path
import hashlib, json, struct, sys, uuid
sys.path.insert(0, str(Path(__file__).resolve().parent.parent/'tools/pydeps'))
import pefile, capstone
from inventory import ROOT

OUT=ROOT/'analysis/hero_sensor_r1'
DONOR='ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP'
HERO='ROG-MAXIMUS-Z790-HERO-ASUS-3001.CAP'
EXPECTED={DONOR:'4545835f46e6b499a19f4ea73a21f2aa6baf61b6bbed5118bd56cf51cdeea205',
          HERO:'f6b3c4c8c879f69eed77ffec6bad587341590e74820a74c27e383318b6b9b96b'}
PARAM='05602C82-5F85-4735-AF53-053502178D02'
BOOTSTRAP='68A0D4CA-9022-474C-BA22-483480DC9A0A'
TRANSPORT='6372357A-06D7-43EF-B55C-1964F3DD6916'
# Historical R1 constant, retained for byte-for-byte reproduction only.
# 2026-09-28: this is NOT the standard PI PCI Enumeration Complete GUID.
# Its use as a hard dependency is a known issue; see hero_sensor_r1/CORRECTION-20260928.md.
PCI_ENUM='72338391-FB43-44A1-A9A2-64FEE1FC5E41'
VAR_ARCH='1E5668E2-8481-11D4-BCF1-0080C73C8881'
VAR_WRITE='6441F818-6362-4E44-B570-7DBA31DD2453'
BMC_READY='D9B90D4F-7F30-4B02-9775-1DC684843C99'
PARAM_PROTO='BB31E7E8-94E0-43CA-AAD0-694CFAB3FF5C'
READY_TO_BOOT='7CE88FB3-4BD7-4679-87A8-A8D8DEE50D2B'
# UEFI ReadyToBoot is 7CE88FB3; 02CE967A is EndOfDxe, not ReadyToBoot.

def sha(b): return hashlib.sha256(b).hexdigest()
def align(n,a=8): return (n+a-1)&-a
def section(t,b):
    n=len(b)+4
    assert n<0xffffff
    return n.to_bytes(3,'little')+bytes([t])+b
def depex(*guids):
    b=b'\x02'+uuid.UUID(guids[0]).bytes_le
    for g in guids[1:]: b+=b'\x02'+uuid.UUID(g).bytes_le+b'\x03'
    return b+b'\x08'
def fix_ffs(h,b):
    h=bytearray(h)
    assert len(h)==24 and len(h)+len(b)<0xffffff
    h[20:23]=(24+len(b)).to_bytes(3,'little')
    h[17]=(-sum(b))&255 if h[19]&0x40 else 0xaa
    h[16]=0
    h[16]=(-(sum(h)-h[17]-h[23]))&255
    return bytes(h)+b
def assert_ffs(b):
    assert len(b)==int.from_bytes(b[20:23],'little')
    assert (sum(b[:24])-b[17]-b[23])&255==0
    assert (sum(b[24:])+b[17])&255==0 if b[19]&0x40 else b[17]==0xaa

class X64:
    """Position-aware emitter for a small, auditable set of x64 instructions."""
    def __init__(self,rva): self.base=rva; self.b=bytearray()
    @property
    def here(self): return self.base+len(self.b)
    def raw(self,h): self.b+=bytes.fromhex(h); return self
    def rel(self,prefix,target):
        p=bytes.fromhex(prefix)
        self.b+=p+struct.pack('<i',target-(self.here+len(p)+4))
        return self

class Module:
    def __init__(self,g):
        self.guid=g
        self.info=next(x for x in db[DONOR] if x['guid']==g)
        self.path=ROOT/self.info['path']
        self.original=(self.path/'header.bin').read_bytes()+(self.path/'body.bin').read_bytes()
        assert sha(self.original)==self.info['sha256']
        self.parts=[]
        for p in sorted((x for x in self.path.iterdir() if x.is_dir()),key=lambda p:int(p.name.split()[0])):
            self.parts.append([p.name,(p/'header.bin').read_bytes()+(p/'body.bin').read_bytes()])
        self.pe_part=next(x for x in self.parts if 'PE32 image' in x[0])
        self.source_image=self.pe_part[1][4:]
        self.image=bytearray(self.source_image)
        self.pe=pefile.PE(data=self.source_image)
        assert self.pe.FILE_HEADER.Machine==0x8664
        self.changes=[]
    def patch(self,rva,end,new,why,expected=None):
        o=self.pe.get_offset_from_rva(rva)
        assert self.pe.get_offset_from_rva(end-1)==o+(end-rva)-1
        old=bytes(self.image[o:o+end-rva])
        if expected is not None: assert old==bytes.fromhex(expected),(self.guid,hex(rva),old.hex())
        assert len(new)<=len(old)
        new=bytes(new)+b'\x90'*(len(old)-len(new))
        self.image[o:o+len(old)]=new
        self.changes.append(dict(rva=hex(rva),file_offset=hex(o),old=old.hex(),new=new.hex(),reason=why))
    def finish(self,dep):
        old=bytes(self.image)
        p=pefile.PE(data=old)
        checksum_off=p.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
        struct.pack_into('<I',self.image,checksum_off,p.generate_checksum())
        self.pe_part[1]=section(0x10,bytes(self.image))
        remaining=[x[1] for x in self.parts if 'dependency' not in x[0]]
        chunks=[section(0x13,dep)]+remaining
        b=b''
        for c in chunks:
            b+=b'\x00'*((4-len(b)%4)%4)+c
        ffs=fix_ffs(self.original[:24],b)
        assert_ffs(ffs)
        path=OUT/'modules'/self.guid
        path.mkdir(parents=True,exist_ok=True)
        (path/'patched.ffs').write_bytes(ffs)
        (path/'patched.efi').write_bytes(self.image)
        cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        listing=[]
        for c in self.changes:
            listing.append(f"\nRVA {c['rva']}: {c['reason']}")
            listing.extend(f'{i.address:08x}: {i.bytes.hex():26} {i.mnemonic} {i.op_str}' for i in cs.disasm(bytes.fromhex(c['new']),int(c['rva'],16)))
        (path/'changes.asm.txt').write_text('\n'.join(listing),encoding='utf-8')
        return ffs,dict(guid=self.guid,original_ffs_sha256=sha(self.original),
             original_pe_sha256=sha(self.source_image),patched_ffs_sha256=sha(ffs),
             patched_pe_sha256=sha(self.image),depex_hex=dep.hex(),changes=self.changes,
             pe_checksum=hex(struct.unpack_from('<I',self.image,checksum_off)[0]),
             source_path=self.info['path'])

def build():
    OUT.mkdir(exist_ok=True)
    originals={n:(ROOT/n).read_bytes() for n in EXPECTED}
    for n,b in originals.items(): assert sha(b)==EXPECTED[n]
    mods=[]

    m=Module(BOOTSTRAP)
    # This driver now waits for PCI enumeration and the variable write service.
    # Replace the fan-control probe registration with a direct card-ready scan.
    # Other two notifications still wait for installation of the IPMI transport.
    x=X64(0x394).raw('33c9').rel('e8',0x420).rel('e9',0x3d4)
    m.patch(0x394,0x3d4,x.b,'Run card-ready scan after PCI enumeration; omit BMC fan-control probe registration.')
    # Allocate and zero the complete shared buffer before publishing it. The
    # original donor allocation left bytes (including list terminators) unset.
    # This scope does not consume the original shared ACPI BAR address field.
    x=X64(0x662).raw('488bf9 488d45d0 4c8bc0 ba80000000 b904000000')
    x.rel('488b05',0x13d8).raw('ff5040 4885c0').rel('0f88',0x7c7)
    x.raw('488b4dd0 ba80000000 4533c0').rel('488b05',0x13d8).raw('ff9068010000')
    x.raw('488365e000 c745e8e8e731bb c745ece094ca43 c745f0aad0694c c745f4fab3ff5c')
    x.raw('488d55e8 4c8b4dd0 488d4de0 4533c0').rel('488b05',0x13d8).raw('ff9080000000').rel('e9',0x7ba)
    m.patch(0x662,0x7ba,x.b,'Zero the full 0x80-byte parameter buffer before protocol publication; omit shared ACPI BAR lookup, unused by this sensor-only scope.')
    # Reuse the original prologue/epilogue, preserving its PE unwind description.
    x=X64(0x1230).raw('488bd9 488d442450 4889442428')
    x.rel('488d05',0x1300).raw('4889442420 4533c9').rel('4c8d05',0xbd8)
    x.raw('ba08000000 b900020000').rel('488b05',0x13d8).raw('ff9070010000 4885c0')
    x.rel('0f88',0x1297).raw('488bcb').rel('488b05',0x13d8).raw('ff5070').rel('e9',0x1297)
    m.patch(0x1230,0x1297,x.b,'Schedule sensor publication on UEFI ReadyToBoot (TPL_CALLBACK), replacing missing AmiTseAfterTimeOut notification.')
    m.patch(0x1300,0x1310,uuid.UUID(READY_TO_BOOT).bytes_le,'Event-group GUID for CreateEventEx.',expected=uuid.UUID('CAD40D6E-C871-4398-910D-2D74EE94711A').bytes_le.hex())
    # The boot-time card scan originally receives an event. Our direct invocation
    # passes NULL, so omit its obsolete CloseEvent. No event lifetime depends on it.
    m.patch(0x609,0x616,b'','Direct card-ready scan has no event to close.')
    x=X64(0xc8e).raw('4885c0').rel('0f88',0x120e).raw('4885c9').rel('0f84',0x120e)
    x.raw('803904').rel('0f85',0x120e).raw('80790102').rel('0f85',0x120e).rel('e9',0xd75)
    m.patch(0xc8e,0xd75,x.b,'Exit cleanly when metadata is missing, null, or not initialized; do not dereference a missing protocol or synthesize legacy defaults.')
    mods.append(m.finish(depex(PCI_ENUM,VAR_ARCH,VAR_WRITE)))

    m=Module(TRANSPORT)
    m.patch(0x1f1a,0x1f29,b'','Keep transport selection in its private structure; omit write to donor-local PCD token 0x0B.',expected='e8c50e00008ad3b90b000000ff5078')
    m.patch(0x1bea,0x1bef,b'','Omit IPMI remote CMOS-clear handling from the sensor bootstrap.',expected='e831080000')
    old_dep=bytes.fromhex(m.info['depex'][0]['hex'])
    mods.append(m.finish(old_dep[:-1]+b'\x02'+uuid.UUID(BMC_READY).bytes_le+b'\x03\x08'))

    m=Module(PARAM)
    # Keep the original main-function prologue and epilogue, but perform only
    # metadata setup. DEPEX guarantees that the 0x80-byte shared buffer exists.
    x=X64(0x568).rel('488915',0x1510).raw('488b4260').rel('488905',0x1500)
    x.raw('488b4258').rel('488905',0x1508).raw('33c9').rel('e8',0x698).raw('33db').rel('e9',0x689)
    m.patch(0x568,0x689,x.b,'Initialize metadata directly; omit donor fan-policy, EndOfDxe and S3 notification registrations and donor PCD token 0x22F.')
    x=X64(0x85f).raw('488b8518100000 c6401f00 41b826000000').rel('e9',0x8af)
    m.patch(0x85f,0x8af,x.b,'Remove all Setup[0xD0F] access; pin fan source to BIOS (0), preserving loop register R8D=0x26.')
    # Match complete 40-byte HERO and donor hardware descriptors except for IDs.
    hwm='062A6204-8C80-4A27-9D09-96654C965894'
    def hwm_image(cap):
        item=next(v for v in db[cap] if v['guid']==hwm)
        return next(p for p in (ROOT/item['path']).rglob('body.bin') if 'PE32 image' in p.parent.name).read_bytes()
    donor_hwm,hero_hwm=hwm_image(DONOR),hwm_image(HERO)
    mappings=[]
    for ins,donor_id,hero_id,do,ho in [(0x8e4,0x238e,0x25ca,0x1480,0x1480),
            (0x8f0,0x239a,0x25d6,0x1520,0x1520), (0x900,0x2394,0x25d0,0x14d0,0x14d0),
            (0x910,0x23c0,0x2600,0x1610,0x1660), (0x920,0x23d4,0x2614,0x1638,0x1688)]:
        a,b=bytearray(donor_hwm[do:do+40]),bytearray(hero_hwm[ho:ho+40])
        assert struct.unpack_from('<H',a,2)[0]==donor_id
        assert struct.unpack_from('<H',b,2)[0]==hero_id
        a[2:4]=b[2:4]=b'\x00\x00'
        assert a==b,(hex(donor_id),hex(hero_id))
        m.patch(ins,ins+5,b'\xb9'+struct.pack('<I',hero_id),'Use HERO HWM identifier matched by the full hardware descriptor.',expected=(b'\xb9'+struct.pack('<I',donor_id)).hex())
        mappings.append(dict(donor=hex(donor_id),hero=hex(hero_id),descriptor_without_id=a.hex()))
    m.patch(0x978,0x97c,bytes.fromhex('c6405200'),'Disable donor BMC fan-control programming, including EC fan masks, in this first sensor-only experiment.',expected='c6405201')
    m.patch(0x9b2,0x9bf,b'','Metadata setup is now a direct call, with no notification event to close.')
    mods.append(m.finish(depex(PARAM_PROTO,VAR_ARCH)))

    cap=bytearray(originals[HERO])
    fvbase=0x12d1000
    free_start=0x1a47f58
    free_end=fvbase+0x9f0000
    assert cap[fvbase+0x28:fvbase+0x2c]==b'_FVH'
    assert struct.unpack_from('<Q',cap,fvbase+0x20)[0]==0x9f0000
    assert all(x==255 for x in cap[free_start:free_end])
    offset=free_start
    for ffs,item in mods:
        offset=align(offset)
        assert offset+len(ffs)<=free_end
        cap[offset:offset+len(ffs)]=ffs
        item['cap_offset']=hex(offset)
        item['ffs_bytes']=len(ffs)
        offset+=len(ffs)
    assert cap[:free_start]==originals[HERO][:free_start]
    assert cap[offset:]==originals[HERO][offset:]
    name='HERO-3001-IPMI-SENSOR-R1-EXPERIMENTAL.CAP'
    (OUT/name).write_bytes(cap)
    (OUT/(name+'.sha256')).write_text(sha(cap)+'  '+name+'\n')
    report=dict(status='EXPERIMENTAL_UNSIGNED_NOT_HARDWARE_VALIDATED',
        purpose='Sensor bootstrap experiment only; no claim of a complete IPMI BIOS port.',
        originals=EXPECTED,output=name,output_sha256=sha(cap),bytes=len(cap),
        insertion_start=hex(free_start),insertion_end_exclusive=hex(offset),
        modified_bytes=sum(a!=b for a,b in zip(cap,originals[HERO])),
        all_bytes_outside_insertion_unchanged=True,original_capsule_header_unchanged=True,
        original_signature_no_longer_authenticates_modified_content=True,
        no_original_ffs_replaced=True,original_hardware_maps_preserved=True,
        hardware_descriptor_id_mappings=mappings,modules=[x[1] for x in mods],
        limitations=['No target boot, BMC response or sensor accuracy validation.',
          'BMC sensor activation list is retained from donor; actual HERO SDR IDs and labels require hardware comparison.',
          'Donor EC/fan-control mask programming is disabled; live fan telemetry is unproven.',
          'No S3 resume, OS IPMI/ACPI interface, remote flash, setup import, FRB/watchdog or PEI IPMI support added.',
          'ASUS capsule authentication, flash-tool acceptance and platform Boot Guard behavior are unverified.',
          'Patched EFI images are internal components, not standalone diagnostics or safe manual-load instructions.'])
    (OUT/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k in ['status','output','output_sha256','modified_bytes','insertion_start','insertion_end_exclusive']},indent=2))
    return report

db=json.loads((ROOT/'analysis/inventory.json').read_text(encoding='utf-8'))
if __name__=='__main__': build()
