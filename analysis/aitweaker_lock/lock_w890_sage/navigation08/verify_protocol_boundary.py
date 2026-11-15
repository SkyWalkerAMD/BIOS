"""Exact original199C4 service ABI; correct the inherited trace label.

No prior source/report is rewritten. BootServices+150 is the variadic
UninstallMultipleProtocolInterfaces slot. The original code presents one
GUID/interface pair and a null next-GUID argument in R9.
"""
from pathlib import Path
import json,hashlib
import verify_lifecycle as l
from verify_lifecycle import TSE,ns
H=Path(__file__).resolve().parent;O=H/'build'
class VM(l.VM):
 def __init__(self):super().__init__();self.uninstall_arguments=[]
 def hook(self,u,address,size,opaque):
  if address==self.uninstall:
   args=[self.arg(i)for i in range(4)]
   assert args==[0x712340,TSE+0x93cd8,TSE+0x93ce8,0]
   assert self.r(args[1],16)==l.ORIG.get_data(0x93cd8,16)
   self.uninstall_arguments.append(args)
  return super().hook(u,address,size,opaque)
def main():
 v=VM();v.ready_full();v.empty_outer_frames();r=v.full(0)
 assert r==0 and not v.unknown and len(v.uninstall_arguments)==1 and not v.protocols and not v.set_count and v.run('w890_provider_query',v.p)==1
 report={'component_sha256':l.SHA,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'dependency_sha256':l.SOURCE_SHA,'checks':1,'cases':[{'name':'original199C4 uses UninstallMultipleProtocolInterfaces with one pair and null terminator','status':'PASS','arguments':v.uninstall_arguments[0],'original_return':0,'service_slot':0x150}],'erratum':'Inherited lifecycle/exit trace label UninstallProtocolInterface at BS+0x150 denotes this variadic service, not single-interface BS+0x90. Prior traces remain unaltered. No control-flow conclusion changes.','limits':'Standard UEFI one-pair successful removal is a checked stateful fixture; not physical service execution.'}
 (O/'protocol_boundary_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
