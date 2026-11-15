"""Read-only local extraction of exact kernel timer-check bytes and evidence."""
from pathlib import Path
import hashlib,json,struct,sys,zlib
OUT=Path(__file__).resolve().parent;LC=OUT.parents[1];ROOT=next(p for p in LC.parents if (p/'tools/pydeps').is_dir());sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone
sha=lambda b:hashlib.sha256(b).hexdigest()
kernel=(LC/'official/vmlinuz-lts').read_bytes();candidate_offsets=[];offset=0;elf=None
while True:
 offset=kernel.find(b'\x1f\x8b\x08',offset)
 if offset<0:break
 candidate_offsets.append(offset);assert len(candidate_offsets)<=32
 try:
  dec=zlib.decompressobj(31);raw=dec.decompress(kernel[offset:],128*1024*1024)
  if dec.eof and raw[:6]==b'\x7fELF\2\1':elf=raw;gzip_offset=offset;gzip_consumed=len(kernel)-offset-len(dec.unused_data);break
 except zlib.error:pass
 offset+=1
assert elf is not None
po=struct.unpack_from('<Q',elf,32)[0];ps,pn=struct.unpack_from('<HH',elf,54);ph=[struct.unpack_from('<IIQQQQQQ',elf,po+i*ps) for i in range(pn)]
def read(addr,n):
 for typ,flags,off,va,pa,fs,ms,align in ph:
  if typ==1 and va<=addr and addr+n<=va+fs:return elf[off+addr-va:off+addr-va+n]
 raise ValueError(hex(addr))
symbols={};ordered=[]
for line in (LC/'review/reference/System.map-6.12.114-0-lts').read_text().splitlines():
 a,t,n=line.split(maxsplit=2);symbols[n]=int(a,16);ordered.append((int(a,16),n,t))
byaddr={a:n for a,n,t in ordered};ordered.sort();md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True;rows=[]
for name in ['timer_irq_works','setup_IO_APIC','__const_udelay','delay_tsc']:
 start=symbols[name];end=min(a for a,n,t in ordered if a>start);data=read(start,end-start);lines=[];calls=[];references=[]
 for ins in md.disasm(data,start):
  comments=[]
  for op in ins.operands:
   if op.type==capstone.x86.X86_OP_IMM and (ins.mnemonic=='call' or ins.mnemonic.startswith('j')) and (op.imm&0xffffffffffffffff) in byaddr:
    dst=op.imm&0xffffffffffffffff;comments.append(byaddr[dst])
    if ins.mnemonic=='call':calls.append({'from':hex(ins.address),'target':hex(dst),'symbol':byaddr[dst]})
   if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
    addr=ins.address+ins.size+op.mem.disp
    if addr in byaddr:comments.append(byaddr[addr]);references.append({'from':hex(ins.address),'address':hex(addr),'symbol':byaddr[addr]})
    if ins.mnemonic=='call':
     try:
      target=struct.unpack('<Q',read(addr,8))[0]
      if target in byaddr:comments.append('initial pointer to '+byaddr[target]);calls.append({'from':hex(ins.address),'pointer_address':hex(addr),'initial_target':hex(target),'symbol':byaddr[target],'runtime_replacement_not_observed':True})
     except ValueError:pass
  lines.append(f'{ins.address:016x} {ins.bytes.hex():28} {ins.mnemonic:8} {ins.op_str}'+(' ; '+', '.join(comments) if comments else ''))
 target=OUT/(name+'.asm.txt');target.write_text('\n'.join(lines)+'\n',encoding='utf8');rows.append({'name':name,'start':hex(start),'end':hex(end),'file_bytes':len(data),'bytes_sha256':sha(data),'listing':target.name,'listing_sha256':sha(target.read_bytes()),'calls':calls,'references':references})
report={'status':'STATIC_EXACT_KERNEL_EXTRACTION','hardware_or_network':False,'kernel_sha256':sha(kernel),'vmlinux_sha256':sha(elf),'vmlinux_bytes':len(elf),'gzip_offset':hex(gzip_offset),'gzip_consumed':gzip_consumed,'candidate_gzip_offsets':[hex(x) for x in candidate_offsets],'system_map_sha256':sha((LC/'review/reference/System.map-6.12.114-0-lts').read_bytes()),'functions':rows}
(OUT/'kernel_timing_bytes.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps({k:report[k] for k in ['kernel_sha256','vmlinux_sha256','vmlinux_bytes','gzip_offset']}));print((OUT/'timer_irq_works.asm.txt').read_text())
