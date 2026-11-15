"""Independent S23 actual machine-code whitelist/bind/publication tests.
Only UEFI HII services and BMC replies are doubled, not production functions.
"""
from pathlib import Path
import gc,hashlib,json,struct,sys,uuid
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
CORE=ROOT/'analysis/hero_p6_s23_20261108'
PIN='1536d23d32c5787820bf61749df1a16bba7e99b755854f2cd4114f7e62e390cc'
assert hashlib.sha256((CORE/'HeroIpmiP6.efi').read_bytes()).hexdigest()==PIN
prior=ROOT/'analysis/hero_p6_settings21r_20261108/tests/test_refresh_lifecycle.py'
ns={'__file__':str(CORE/'tests/independent_fixture.py'),'__name__':'fixture_definitions'}
exec(compile(prior.read_text().split('\nrows=[]')[0],str(prior),'exec'),ns)
Fixture=ns['Machine'];v=ns['v'];langs=ns['langs'];ids=ns['ids']
from unicorn.x86_const import *
forms5=(CORE/'native/Setup-forms-P5.bin').read_bytes();forms6=(CORE/'native/Setup-forms-P6.bin').read_bytes()
assert 'int p5_package_matches(const uint8_t *b,UN n){return p5_package_kind(b,n)==RESOURCE_P6;}' in (CORE/'source/publisher.c').read_text()
assert hashlib.sha256(forms5).hexdigest()=='b295f8ce9b5f38f366f3cf8c9c8895f218bd009c2a9c9144ea2ff6c5ff3f98c8'
assert hashlib.sha256(forms6).hexdigest()=='3ec34187a90cfefeac1728a8e7b67e447d6bafc07d5d30d61d4396c94c0fef08'
old=json.loads((ROOT/'analysis/hero_ipmi_p5/native-payload.json').read_text())
assert list(old['value_ids'].values())==ids[:40] and len(ids)==41
def pack(*forms):
    body=b''.join(forms)+b'\x04\0\0\xdf'
    return uuid.UUID('a85810b5-ad33-4350-b7f5-37905d0dbdb9').bytes_le+struct.pack('<I',20+len(body))+body
P5=pack(forms5);P6=pack(forms6)
def unknown(package):
    p=bytearray(package);p[100]^=1;return bytes(p)

class Machine(Fixture):
    def __init__(self,packages=(P5,)):
        super().__init__();self.packages={100+i:p for i,p in enumerate(packages)}
        self.export_error=None;self.missing=None;self.gets=[];self.sets=[]
    def hook(self,u,addr,size,ctx):
        name=self.stubs.get(addr)
        if not name:return
        sp=u.reg_read(UC_X86_REG_RSP)
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        e=self.r64(sp+0x28);f=self.r64(sp+0x30)
        if name=='HiiList':
            assert a==self.db and (b&255)==2 and c==0
            n=len(self.packages)*8
            if not e:self.w64(d,n);return self.ret(u,v.ERR(5),name)
            assert self.r64(d)>=n
            u.mem_write(e,b''.join(struct.pack('<Q',h) for h in self.packages));self.w64(d,n)
            return self.ret(u,0,name)
        if name=='HiiExport':
            assert a==self.db and b in self.packages
            if self.export_error==b:return self.ret(u,v.ERR(7),name)
            raw=self.packages[b]
            if not d:self.w64(c,len(raw));return self.ret(u,v.ERR(5),name)
            assert self.r64(c)>=len(raw);u.mem_write(d,raw);self.w64(c,len(raw));return self.ret(u,0,name)
        if name=='HiiGet':
            assert a==self.strings and c in self.packages
            key=(self.cstr(b),d&65535);self.gets.append(key)
            if key==self.missing:return self.ret(u,v.ERR(14),name)
            raw=(self.hii[key]+'\0').encode('utf-16le')
            assert self.r64(f)>=len(raw);u.mem_write(e,raw);self.w64(f,len(raw));return self.ret(u,0,name)
        if name=='HiiSet':
            assert a==self.strings and b in self.packages
            key=(self.cstr(d),c&65535);assert key in self.hii
            self.hii[key]=self.wide(e);self.sets.append(key);self.hii_sets.append(key);return self.ret(u,0,name)
        return super().hook(u,addr,size,ctx)
    def quiet(self):
        assert not self.pools and not self.dev.packets and not self.dev.mutations and not self.nv_writes and not self.pci_writes

rows=[]
def run(name,fn):
    fn();rows.append({'case':name,'passed':True});print(name,'PASS',flush=True);gc.collect()
for name,raw,kind in [('exactP5',P5,1),('exactP6',P6,2),('changedP5',unknown(P5),0),('changedP6',unknown(P6),0),
                      ('mixedBoth',pack(forms5,forms6),0xffffffff),('duplicateP5',pack(forms5,forms5),0xffffffff),
                      ('noForms',pack(),0xffffffff),('truncated',P5[:-1],0xffffffff),('tail',P6+b'\0',0xffffffff)]:
    def check(raw=raw,kind=kind):
        m=Machine();p=m.alloc(raw)
        assert m.call('p5_package_kind',p,len(raw))&0xffffffff==kind
        m.quiet()
    run('classifier_'+name,check)
for kind,package,count in [('P5',P5,40),('P6',P6,41)]:
    def good(package=package,count=count):
        m=Machine((unknown(P5),package));assert m.call('p5_bind')==0
        assert len(m.gets)==count*len(langs)
        assert m.call('p5_publish')==0 and len(m.sets)==count*len(langs)
        assert set(m.sets)=={(l,i) for l in langs for i in ids[:count]}
        assert all(m.hii[(l,ids[40])]=='Not queried' for l in langs) if count==40 else True
        m.quiet()
    run('all_languages_exact_count_'+kind,good)
for packages in ((P5,P6),(P5,P5),(P6,P6)):
    def reject(packages=packages):
        m=Machine(packages);assert m.call('p5_bind')!=0 and not m.gets and not m.sets;m.quiet()
    run('ambiguous_'+str([len(x) for x in packages]),reject)
def failed_later():
    m=Machine((P5,P6));m.export_error=101
    assert m.call('p5_bind')!=0 and not m.gets and not m.sets;m.quiet()
run('later_export_failure_not_hidden_after_known_target',failed_later)
def malformed_later():
    m=Machine((P5,P6[:-1]));assert m.call('p5_bind')!=0 and not m.sets;m.quiet()
run('later_malformed_list_not_hidden',malformed_later)
for package,count in ((P5,40),(P6,41)):
    def missing(package=package,count=count):
        m=Machine((package,));m.missing=(langs[-1],ids[count-1]);assert m.call('p5_bind')!=0 and not m.sets;m.quiet()
    run('missing_last_value_final_language_'+str(count),missing)
def p5_omits_config():
    m=Machine();m.missing=(langs[-1],ids[40]);assert m.call('p5_bind')==0 and m.call('p5_publish')==0
    assert len(m.sets)==40*len(langs);m.quiet()
run('P5_does_not_probe_or_set_P6_only_config_ID',p5_omits_config)
for original,new in ((P5,P6),(P6,P5),(P5,unknown(P5))):
    def changed(original=original,new=new):
        m=Machine((original,));assert m.call('p5_bind')==0;m.packages[100]=new
        assert m.call('p5_publish')!=0 and not m.sets;m.quiet()
    run('publish_rechecks_exact_kind_'+str((len(original),len(new))),changed)
def changed_string():
    m=Machine();assert m.call('p5_bind')==0;m.missing=(langs[-1],ids[39])
    assert m.call('p5_publish')!=0 and not m.sets;m.quiet()
run('publish_prechecks_all_IDs_before_first_Set',changed_string)
report={'passed':True,'count':len(rows),'results':rows,'core_sha256':PIN,
        'languages':langs,'p5_values':40,'p6_values':41,
        'scope':'Actual S23 machine code for classifier, HII bind and publication. Synthetic HII service response buffers only. No production function replaced; no target device access.',
        'no_BMC_PCI_NV_operations_in_these_cases':True}
(OUT/'dual-resource-actual-pe-review.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'passed':True,'cases':len(rows),'core_sha256':PIN},indent=2))
