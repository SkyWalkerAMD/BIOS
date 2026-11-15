"""Exact offline instruction evidence: known caller is Redfish ResetBios chain."""
from pathlib import Path
import sys,json,hashlib,uuid
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone as C
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
scan=json.loads((HERE/'initializer_callers.json').read_text())
row=next(x for x in scan['modules']if x['sha256'].startswith('cfbbd0'))
source=Path(row['file']);assert sha(source)==row['sha256'];p=pefile.PE(str(source))
cs=C.Cs(C.CS_ARCH_X86,C.CS_MODE_64);cs.detail=True
def strings(rva):return p.get_data(rva,300).split(b'\0')[0].decode('ascii')
def decode(start,end):
 return [{'rva':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str,
          'RIP_targets':[hex(i.address+i.size+o.mem.disp)for o in i.operands if o.type==C.x86_const.X86_OP_MEM and o.mem.base==C.x86_const.X86_REG_RIP]}for i in cs.disasm(p.get_data(start,end-start),start)]
assert strings(0x145b8)=='ResetBios'and strings(0x145c4)=='true'
assert p.get_data(0x1284,3)==bytes.fromhex('ff5010')
assert p.get_data(0x13278,16)==uuid.UUID(scan['protocol_guid']).bytes_le
assert decode(0x2b3e,0x2b45)[0]['RIP_targets']==['0x159b9']
assert decode(0x1245,0x124c)[0]['RIP_targets']==['0x159b9']
r={'status':'FROZEN_NATIVE_REDFISH_RESETBIOS_TO_AMITSE_DEFAULT_SAVE_CHAIN','module_FFS_GUID':'1c5c6e7e-552a-443e-9a04-7408adee99d3',
 'module_sha256':sha(source),'source_module':str(source),'original_CAP_sha256':scan['CAP_sha256'],'protocol_GUID':scan['protocol_guid'],
 'registration_AMITSE':'5F61B interface79050,5F625 GUID6B3A0,5F633 InstallProtocolInterface; method slot79060 points5F688',
 'instruction_regions':{'GET_defaults_request':decode(0x1080,0x109d),'parse_then_request':decode(0x122d,0x129e),
 'JSON_parser_dispatch':decode(0x2d88,0x2dff),'reset_field_and_value_compare':decode(0x2881,0x28e8),'set_reset_flag':decode(0x2b3e,0x2b60)},
 'string_literals':{hex(x):strings(x)for x in [0x145b8,0x145c4,0x14ff0,0x14130,0x14450]},
 'directly_supported':['The original module constructs GET /redfish/v1/bios/defaultSD.',
 'Mode2 node handling compares field ResetBios and value true; success sets native byte159B9=1.',
 'After parser2D88(mode2) succeeds, native1245 checks159B9 then LocateProtocol57E61629; method call1284 uses the returned interface at stack+48 and slot10.',
 'Original AMITSE registers this protocol at interface79050 with slot10=5F688, which calls defaults then native save1425C.'],
 'not_established':['This evidence does not prove a physical CMOS-reset or normal first-boot variable-initialization caller.','No network/BMC operation was performed and no runtime Redfish request was submitted.','Bounded GUID/reference search is not a closed-world proof that no other indirect caller exists.'],
 'decision':'Do not add missing-variable initialization authorization. Native12 only propagates existing local ACCESS_DENIED back to native save callers.',
 'source_sha256':sha(Path(__file__)),'reference_scan_sha256':sha(HERE/'initializer_callers.json')}
(HERE/'reset_call_chain.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'status':r['status'],'sha256':sha(HERE/'reset_call_chain.json')}))
