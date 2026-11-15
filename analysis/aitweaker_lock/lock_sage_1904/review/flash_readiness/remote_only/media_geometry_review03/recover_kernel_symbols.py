"""Recover the embedded kallsyms table from this one pinned public kernel."""
import json,struct,hashlib
from kernel_targets import HERE,KERNEL,EXPECTED

def main():
    raw=KERNEL.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
    anchor=0xc25054
    dictionaries=[]
    for idx in range(anchor&~3,anchor+8192,4):
        arr=struct.unpack_from('<256H',raw,idx)
        if arr[0]!=0 or not 255<=arr[-1]<8192 or any(arr[i]>=arr[i+1] for i in range(255)):continue
        for end in range(idx-3,idx+1):
            if raw[end-1]!=0:continue
            start=end-1
            for unused in range(256):
                start=raw.rfind(b'\0',max(0,start-512),start)
                if start<0:break
            if start<0:continue
            start+=1
            toks=raw[start:end].split(b'\0')[:-1]
            positions=[];pos=0
            for t in toks:positions.append(pos);pos+=len(t)+1
            if len(toks)==256 and tuple(positions)==arr:
                dictionaries.append((start,idx,toks))
    assert len(dictionaries)==1,[(hex(a),hex(b)) for a,b,c in dictionaries]
    tokstart,tokindex,tokens=dictionaries[0]
    # Find long sorted absolute-address ranges; the real table is immediately
    # followed by its own symbol count, then bounded compressed names.
    words=struct.unpack('<'+'I'*(len(raw)//4),raw[:len(raw)&~3])
    runs=[];runstart=None;last=0
    for i,w in enumerate(words):
        valid=0x80008000<=w<=0x82008000
        if valid and (runstart is None or w>=last):
            if runstart is None:runstart=i
        else:
            if runstart is not None and i-runstart>=1000:runs.append((runstart*4,i*4,i-runstart))
            runstart=i if valid else None
        last=w
    result=None
    candidates=[(start,end,nrun,None) for start,end,nrun in runs]
    for off in range(max(0,tokstart-3*1024*1024),tokstart,4):
        base,count=struct.unpack_from('<II',raw,off)
        if base==0x80008000 and 1000<=count<=200000 and off>=count*4:
            candidates.append((off-count*4,off+4,count,base))
    for start,end,nrun,base in candidates:
        count=struct.unpack_from('<I',raw,end)[0]
        if not 1000<=count<=nrun:continue
        addstart=end-count*4-(4 if base else 0);namesstart=end+4;p=namesstart;syms=[];markers=[]
        for j in range(count):
            if j%256==0:markers.append(p-namesstart)
            n=raw[p];p+=1
            if n==0 or n>127 or p+n>=tokstart:break
            text=b''.join(tokens[x] for x in raw[p:p+n]);p+=n
            if any(x<32 or x>126 for x in text):break
            addr=struct.unpack_from('<I',raw,addstart+j*4)[0]
            if base is not None:addr=(base+addr)&0xffffffff
            syms.append({'name':text[1:].decode('ascii'),'type':chr(text[0]),'address':hex(addr)})
        if len(syms)!=count:continue
        markstart=(p+3)&~3
        actual=list(struct.unpack_from('<'+'I'*len(markers),raw,markstart))
        if actual!=markers:continue
        if (markstart+4*len(markers)+3)&~3!=tokstart:continue
        result={'count':count,'addresses_offset':hex(addstart),'names_offset':hex(namesstart),
                'markers_offset':hex(markstart),'tokens_offset':hex(tokstart),'token_index_offset':hex(tokindex),
                'relative_base':hex(base) if base else None,'symbols':syms};break
    if result is None:
        out={'dictionary':{'tokens':hex(tokstart),'index':hex(tokindex)},'address_runs':runs};print(json.dumps(out));raise ValueError('No validated symbol table')
    result['kernel_sha256']=EXPECTED;result['scope']='validated names/count/address/marker table from pinned kernel; no code executed'
    (HERE/'kernel_symbols.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    selected=[x for x in result['symbols'] if x['name'].startswith('nbd_') or x['name'].startswith('fsg_lun_') or x['name'] in ['do_read_capacity','do_read_capacity_16','fsg_common_thread','fsg_main_thread','fsg_store_file']]
    (HERE/'kernel_selected_symbols.json').write_text(json.dumps(selected,indent=2),encoding='utf8');print(json.dumps({'table':{k:v for k,v in result.items() if k!='symbols'},'selected':selected},indent=2))
if __name__=='__main__':main()
