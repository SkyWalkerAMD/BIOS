"""Adapt the prior strict delivered-PE harness to ReadFile-body I2B behavior."""
from pathlib import Path
P=Path(__file__).resolve().parent
def main():
 old=(P.parent/'i2-build/verify_i2.py').read_text()
 old=old.replace('I2','I2B').replace('verify_i2.py','verify_i2b.py')
 old=old.replace("LI='5b1b31a1", "P1API='4c8dd4ac-6827-4431-b9c7-0ad41e871db1'\nLI='5b1b31a1")
 old=old.replace("PE={R2:makepe(0x52),P5:makepe(0x50)}", """PE={R2:makepe(0x52),P5:makepe(0x50)}
def section(kind,payload):
 b=(len(payload)+4).to_bytes(3,'little')+bytes([kind])+payload
 return b+bytes(-len(b)%4)
BODY={g:section(0x13,b'\\x06\\x08')+section(0x10,p)+section(0x15,b'T\\0\\0\\0') for g,p in PE.items()}
""")
 old=old.replace("handled={'GetMap'", "handled={'Locate','GetMap'")
 old=old.replace("  if name=='GetMap':", """  if name=='Locate':
   guid=self.guid(a);assert guid in [base.API,P1API,base.P6API,base.GOP]
   if self.scenario=='api_present' and guid!=base.GOP:self.w64(c,self.svc if guid==base.API else self.p6svc)
   else:status=base.ERR(14)
  elif name=='GetMap':""")
 start=old.index("  elif name=='FvReadFile':")
 end=old.index("  elif name=='FileRead':",start)
 old=old[:start]+"""  elif name=='FvReadFile':
   assert a==self.fv;guid=self.guid(b);assert guid in BODY
   if self.scenario=='absent_r2' and guid==R2:status=base.ERR(14)
   else:
    u.mem_write(self.r64(rsp+40),b'\\x07');u.mem_write(self.r64(rsp+48),struct.pack('<I',0x200))
    if not c:self.w64(d,1048577 if self.scenario=='large_file' else len(BODY[guid]))
    else:
     allocated=self.r64(c)==0
     if not allocated and self.scenario=='allocate_only':status=base.ERR(2)
     elif self.scenario=='body_warning':self.w64(d,len(BODY[guid])+1);status=4
     elif self.scenario=='body_changed':self.w64(d,len(BODY[guid])+1)
     else:
      if allocated:self.w64(c,self.alloc(BODY[guid]))
      else:
       assert self.r64(d)==len(BODY[guid]);u.mem_write(self.r64(c),BODY[guid])
      if self.scenario=='bad_sections':u.mem_write(self.r64(c),bytes(4))
      self.w64(d,len(BODY[guid]));u.mem_write(self.r64(rsp+56),bytes(4))
  elif name=='FvReadSection':raise AssertionError('ReadSection must not be called by I2B')
"""+old[end:]
 old=old.replace("('section_warning_no_hash',{'scenario':'section_warning'},base.ERR(33)),", """('body_warning_no_hash',{'scenario':'body_warning'},base.ERR(33)),
  ('changed_body_size_no_hash',{'scenario':'body_changed'},base.ERR(33)),
  ('readfile_null_allocate_compatibility',{'scenario':'allocate_only'},0),
  ('bad_section_stream_preserves_body_crc',{'scenario':'bad_sections'},base.ERR(33)),
  ('api_presence_no_methods',{'scenario':'api_present'},0),""")
 old=old.replace("assert not any(x.startswith(('FORBIDDEN','R2','P6')) for x in m.calls)","assert not any(x.startswith(('FORBIDDEN','R2','P6')) for x in m.calls) and 'FvReadSection' not in m.calls")
 old=old.replace("if 'warning' in name:assert b'FP_FV_PE_CRC32=' not in log", """if 'warning' in name or 'changed_body' in name:assert b'FP_FV_PE_CRC32=' not in log and b'FP_FV_BODY_CRC32=' not in log
   if name=='readfile_null_allocate_compatibility':
    assert b'FP_FV_BODY_ALLOC_STATUS=0000000000000000' in log and b'FP_FV_BODY_ALLOC_FREE_STATUS=0000000000000000' in log
   if name=='bad_section_stream_preserves_body_crc':assert b'FP_FV_BODY_CRC32=' in log and b'FP_FV_PE_CRC32=' not in log
   if name=='api_presence_no_methods':assert b'FP_API_LOCATE_STATUS=0000000000000000' in log and b'FP_API_METHODS_NOT_CALLED' in log""")
 (P/'verify_i2b.py').write_text(old,encoding='ascii',newline='\n')
 vm=(P.parent/'i2-build/run_vm.py').read_text().replace('I2','I2B')
 (P/'run_vm.py').write_text(vm,encoding='ascii',newline='\n')
 print('Prepared I2B delivered-PE and OVMF harnesses.')
if __name__=='__main__':main()
