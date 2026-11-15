"""Rerun the unchanged adapter suite against the isolated candidate binary.

The old fixture omitted native history; add an initialized Ai-root history,
which original BrowserLoop establishes before its first polling iteration.
"""
from pathlib import Path
HERE=Path(__file__).resolve().parent;DRIVER=HERE.parent.parent/'driver'
source=(DRIVER/'verify_adapter.py').read_text(encoding='utf8')
source=source.replace("HERE/'build/driver.map'","CANDIDATE/'build/driver.map'")
source=source.replace("HERE/'build/AiTweakerLock1904.efi'","CANDIDATE/'build/AiTweakerLock1904.efi'")
source=source.replace("HERE/'build/adapter_emulation.json'","CANDIDATE/'adapter_emulation.json'")
prefix,body=source.split('\nchecks=[]',1)
ns={'__file__':str(DRIVER/'verify_adapter.py'),'CANDIDATE':HERE}
exec(compile(prefix,str(DRIVER/'verify_adapter.py'),'exec'),ns)
BaseVM=ns['VM'];TSE=ns['TSE'];HEAP=ns['HEAP'];q=ns['q'];d=ns['d'];w=ns['w']
class VM(BaseVM):
 def __init__(self):
  super().__init__()
  for i,p in enumerate(self.pages):
   form=int.from_bytes(self.u.mem_read(self.records+i*64+10,2),'little')
   self.u.mem_write(p+0x2a,w(form))
  history=HEAP+0x180000
  self.u.mem_write(TSE+0x835a0,q(history));self.u.mem_write(TSE+0x83598,d(28))
  self.u.mem_write(TSE+0x83594,d(1));self.u.mem_write(TSE+0x835b8,d(1))
  self.u.mem_write(history,q(self.handle)+d(0x2714))
ns['VM']=VM
exec(compile('\nchecks=[]'+body,str(DRIVER/'verify_adapter.py'),'exec'),ns)
