from map_w890 import *
module=sys.argv[1];side=OLD if sys.argv[2]=='old' else NEW
data=image(side/(module+'.efi'))
for arg in sys.argv[3:]:
    start,n=map(lambda s:int(s,0),arg.split(':'))
    print(f'RANGE {module} {side.name} {start:#x} {n:#x}')
    for x in cs.disasm(data[start:start+n],start):print(f'{x.address:08x} {x.bytes.hex():24} {x.mnemonic} {x.op_str}')
