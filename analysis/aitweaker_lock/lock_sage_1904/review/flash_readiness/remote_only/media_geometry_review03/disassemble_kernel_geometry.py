"""Disassemble only pinned kernel's relevant geometry functions."""
import json,sys,hashlib
from kernel_targets import HERE,KERNEL,EXPECTED
from trace_nbd import ROOT
sys.path.insert(0,str(ROOT/'tools/pydeps'))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN

SELECT=['nbd_size_update','nbd_alloc_config','nbd_ioctl','nbd_config_put','nbd_open','nbd_start_device',
        'fsg_lun_open','fsg_store_file','fsg_main_thread']

def main():
    raw=KERNEL.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
    symbols=json.loads((HERE/'kernel_symbols.json').read_text())['symbols']
    byaddr={int(x['address'],16):x['name'] for x in symbols}
    addresses=sorted(set(int(x['address'],16) for x in symbols))
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    md.skipdata=True
    rows=[];strings=[]
    outdir=HERE/'kernel_disassembly';outdir.mkdir(exist_ok=True)
    for name in SELECT:
        matches=[x for x in symbols if x['name']==name];assert len(matches)==1
        address=int(matches[0]['address'],16);end=addresses[addresses.index(address)+1]
        offset=address-0x80008000;data=raw[offset:offset+end-address]
        rows.append({'name':name,'address':hex(address),'end':hex(end),'file_offset':hex(offset),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        lines=[]
        for i in md.disasm(data,address):
            annotation=''
            if i.mnemonic in ['bl','b','blx'] and i.op_str.startswith('#'):
                dest=int(i.op_str[1:],16)
                if dest in byaddr:annotation=' ; '+byaddr[dest]
            lines.append(f'{i.address:08x} {i.bytes.hex():8s} {i.mnemonic:8s} {i.op_str}{annotation}')
        (outdir/(name+'.txt')).write_text('\n'.join(lines),encoding='utf8')
    (HERE/'kernel_function_ranges.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
    print(json.dumps(rows,indent=2))
if __name__=='__main__':main()
