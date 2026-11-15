"""Static-only call/dataflow evidence for safe_system's raw status contract."""
import json
from analyze_geometry import HERE, Elf32, sha
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
md=Cs(CS_ARCH_ARM,CS_MODE_ARM);md.skipdata=True
def write_range(e,a,z,label):
    off=e.offset(a,z-a);assert off is not None
    b=e.data[off:off+z-a];lines=[]
    for i in md.disasm(b,a):
        tail=''
        if i.mnemonic in ('b','bl','blx') and i.op_str.startswith('#'):tail=e.names.get(int(i.op_str[1:],0),'')
        lines.append(f'{i.address:08x} {i.bytes.hex()} {i.mnemonic} {i.op_str} {tail}')
    p=HERE/'disassembly'/(label+'.txt');p.write_text('\n'.join(lines)+'\n',encoding='utf8')
    return {'start':hex(a),'end':hex(z),'bytes_sha256':sha(b),'listing':str(p.relative_to(HERE))}
def main():
    lib=Elf32(HERE/'official_inputs/5308416/usr/local/lib/libsafesystem.so.13.1.1')
    daemon=Elf32(HERE/'official_inputs/5308416/usr/local/bin/execdaemon')
    ranges=[write_range(lib,0x13bc,0x13c0,'safe_system'),write_range(lib,0xeb4,0x125c,'safe_system_exec'),
            write_range(daemon,0x10dac,0x10e54,'execdaemon_status_return')]
    out={'status':'STATIC_DATAFLOW_CONFIRMED','sources':[{'path':str(e.path),'sha256':sha(e.data)} for e in [lib,daemon]],
         'ranges':ranges,'findings':[
             'safe_system ELF0x13BC branches to safe_system_exec via PLT0xC44.',
             'safe_system_exec sends a command to /var/execdaemon_pipe and receives a 4-byte status from /var/execdaemon_rep.<tid>. At0x1098 the received word is returned unchanged.',
             'execdaemon at0x10DB0 calls system;0x10DBC retains its return inR5;0x10DF0 stores that exact value atSP+8;0x10E1C writes those4bytes back. No status-to-negative normalization on the inspected success transport path.',
             'Therefore the hdisk_start check of only negative safe_system results does not reject a positive nonzero system wait status. New native attach test explicitly models256 and observes success; no real shell error was induced.',
             'The trailing ampersand in the file-attribute echo means even shell completion does not establish completion/success of that background attribute write.'
         ],'limits':'No target process, FIFO, shell, command or syscall was executed. The ABI/return-word dataflow is static evidence, not live status observation.'}
    (HERE/'safe_system_contract.json').write_text(json.dumps(out,indent=2),encoding='utf8')
    print(json.dumps({'status':out['status'],'ranges':len(ranges)}))
if __name__=='__main__':main()
