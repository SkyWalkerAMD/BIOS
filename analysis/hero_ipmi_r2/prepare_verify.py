"""Carry forward the established hardware-replay fault matrix to R2."""
from pathlib import Path
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
s=(ROOT/'analysis/hero_ipmi_setup_m1/verify.py').read_text()
s=s.replace('actual M1 DXE','actual R2 DXE').replace('HeroIpmiM1.efi','HeroIpmiR2.efi')
s=s.replace("if case in ('disabled','auto_disabled'):self.vars={}","if case in ('disabled','auto_disabled'):self.vars={'HeroIpmiCfg':(3,GOOD[:4]+b'\\0'+GOOD[5:])}")
s=s.replace("        self.hstr=self.alloc(bytes(24));self.stub(self.hstr+16,'HiiSetString');self.w64(self.functions['strings'],self.hstr)","        self.w64(self.functions['installed'],1) # Isolated callback tests model an active core.")
s=s.replace("elif name=='HiiSetString':self.hii_values[c&65535]=self.wide(e)","elif name=='HiiSetString':raise AssertionError('R2 core must not use HII')")
s=s.replace("        action_request=m.alloc(bytes(8))\n        assert m.call('callback',0,1,5,0,0,action_request)==0","        assert m.call('api_unlock')==(ERR(15) if enabled else 0)")
start=s.index('    m=Machine();request=m.alloc(bytes(8));')
end=s.index("    (OUT/'verification.json')",start)
s=s[:start]+'''    m=Machine();assert m.call('api_run',2)==ERR(2) and not m.dev.packets
    rows.append(dict(case='api_rejects_unknown_operation',passed=True))
    m=Machine();m.vars={};cfg=m.alloc(bytes(8));source=m.alloc(bytes(4))
    assert m.call('api_config',cfg,source)==0
    assert bytes(m.u.mem_read(cfg,8))==GOOD and m.r64(source)&0xffffffff==0 and not m.nv_writes
    assert m.call('api_enable',0)==0 and m.vars['HeroIpmiCfg'][1][4]==0
    assert m.call('api_enable',0)==0 and len(m.nv_writes)==1
    rows.append(dict(case='missing_default_enabled_explicit_disable_persisted',passed=True))
    m=Machine();m.vars={};assert m.call('api_enable',1)==0 and m.vars['HeroIpmiCfg'][1]==GOOD
    rows.append(dict(case='explicit_enable_creates_record_even_when_default_matches',passed=True))
''' +s[end:]
s=s.replace("'QEMU HII results are recorded separately.'","'Entry lifecycle and actual QEMU console tests are recorded separately.'")
(OUT/'verify.py').write_text(s,encoding='utf-8')
print('R2 replay matrix prepared.')
