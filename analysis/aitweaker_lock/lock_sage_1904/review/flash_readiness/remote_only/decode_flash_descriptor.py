"""Offline PCH700 descriptor interpretation; never authorize reads from masks."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,re,struct
HERE=Path(__file__).resolve().parent
HW=HERE.parents[2]/'remote_172_20_2_162'
ROOT=HERE.parents[5]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
names=['Descriptor','BIOS','ME','GbE','PlatformData','DeviceExpansion','SecondaryBIOS','Region7','EC','DeviceExpansion2','IE','10GbE0','10GbE1','Region13','Region14','PTT']

def decode(blob):
    if len(blob)!=4096:raise ValueError('Expected exactly 4096 captured bytes')
    def word(offset):return struct.unpack_from('<I',blob,offset)[0]
    if word(0x10)!=0x0ff0a55a:raise ValueError('Descriptor signature mismatch')
    map0,map1,map2=word(0x14),word(0x18),word(0x1c)
    fcba=(map0&255)<<4;frba=((map0>>16)&255)<<4;fmba=(map1&255)<<4
    tables=[(fcba,12,'component'),(frba,64,'16 regions'),(fmba,4,'host master')]
    for offset,size,label in tables:
        if offset<0x20 or offset+size>4096:raise ValueError('Table outside descriptor: '+label)
    for i,(offset,size,label) in enumerate(tables):
        if any(max(offset,o)<min(offset+size,o+n) for o,n,_ in tables[:i]):raise ValueError('Overlapping tables')
    nc=(map0>>8)&3
    if nc>1:raise ValueError('Unsupported component count')
    comp=word(fcba);density=[(comp>>(4*i))&15 for i in range(nc+1)]
    if any(n>7 for n in density):raise ValueError('Density outside reviewed PCH700 profile')
    capacity=[1<<(19+n) for n in density];total=sum(capacity)
    master=word(fmba)
    readmask=((master>>8)&0xfff)|((master&15)<<12)
    writemask=((master>>20)&0xfff)|(((master>>4)&15)<<12)
    regions=[]
    for i in range(16):
        raw=word(frba+4*i);base=(raw&0x7fff)<<12;limit=(((raw>>16)&0x7fff)<<12)|4095
        enabled=base<=limit
        regions.append({'slot':i,'name':names[i],'raw':f'{raw:08X}','enabled':enabled,
                        'base':base,'limit_inclusive':limit,'bytes':limit-base+1 if enabled else 0,
                        'descriptor_host_read_grant':bool(readmask&(1<<i)),
                        'descriptor_host_write_grant':bool(writemask&(1<<i)),
                        'effective_runtime_permission_confirmed':i==0,
                        'within_configured_capacity':limit<total if enabled else None,
                        'reserved_bits':f'{raw&0x80008000:08X}'})
    enabled=sorted((r for r in regions if r['enabled']),key=lambda r:r['base'])
    if regions[0]['base']!=0 or regions[0]['limit_inclusive']!=4095:raise ValueError('Unexpected descriptor region bounds')
    if any(not r['within_configured_capacity'] or r['reserved_bits']!='00000000' for r in enabled):raise ValueError('Enabled region is malformed or exceeds configured capacity')
    if any(a['limit_inclusive']>=b['base'] for a,b in zip(enabled,enabled[1:])):raise ValueError('Enabled regions overlap')
    holes=[];position=0
    for r in enabled:
        if position<r['base']:holes.append({'base':position,'limit_inclusive':r['base']-1})
        position=r['limit_inclusive']+1
    if position<total:holes.append({'base':position,'limit_inclusive':total-1})
    return {'map0':f'{map0:08X}','map1':f'{map1:08X}','map2':f'{map2:08X}',
            'component_offset':fcba,'region_offset':frba,'host_master_offset':fmba,
            'component_raw':f'{comp:08X}','component_count':nc+1,'density_codes':density,
            'component_configured_bytes':capacity,'total_configured_bytes':total,
            'host_master_raw':f'{master:08X}','descriptor_host_read_mask':f'{readmask:04X}',
            'descriptor_host_write_mask':f'{writemask:04X}','regions':regions,'unclassified_holes':holes,
            'independent_JEDEC_or_SFDP_capacity_proof':False,
            'regions_covered_by_successful_capture':[0]}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('folder');args=parser.parse_args()
    if not re.fullmatch(r'hardware-spifd(01|02)-[0-9]+',args.folder):raise ValueError('Unexpected capture folder')
    version=re.search(r'spifd(\d+)',args.folder)[1];folder=HW/args.folder
    dp=HW/f'read_spi_descriptor{version}_qr.py'
    spec=importlib.util.spec_from_file_location('capture_parser',dp)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    raw=(folder/'hardware-log.txt').read_bytes();blob,result=mod.parse_descriptor(raw)
    manifest=json.loads((folder/'manifest.json').read_text())
    if manifest['sha256']!=hashlib.sha256(raw).hexdigest():raise ValueError('Log manifest mismatch')
    out={'status':result['status'],'capture':result,'log':{'path':str(folder/'hardware-log.txt'),'sha256':sha(folder/'hardware-log.txt')},
         'manifest':{'path':str(folder/'manifest.json'),'sha256':sha(folder/'manifest.json')},
         'parser_sha256':sha(dp),'decoder_sha256':sha(Path(__file__)),'decoded':None,
         'complete_spi_backup':False,'recovery_tested':False,'firmware_flashing_performed':False}
    if blob is not None:
        target=folder/'hardware-descriptor.bin'
        if target.read_bytes()!=blob:raise ValueError('Descriptor/log mismatch')
        out['decoded']=decode(blob);out['descriptor']={'path':str(target),'bytes':4096,'sha256':sha(target)}
        out['decoded']['FREG0_through_5_match_prior_INV04']=[r['raw'] for r in out['decoded']['regions'][:6]]==['00000000','3FFF3000','06920001','00007FFF','00007FFF','00007FFF']
        cap=ROOT/'analysis/aitweaker_lock/official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
        if sha(cap)!='aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3':raise ValueError('Official reference mismatch')
        image=cap.read_bytes();header=struct.unpack_from('<I',image,16)[0]
        if header!=4096:raise ValueError('Official capsule header mismatch')
        reference=image[header:header+4096]
        out['official_reference']={'path':str(cap),'sha256':sha(cap),'descriptor_identical':reference==blob,
                                   'differing_bytes':sum(a!=b for a,b in zip(reference,blob)),
                                   'scope':'Only the descriptor comparison, not identity of the installed full firmware.'}
    out['limits']=['Only successfully captured region0 bytes are established; all other contents remain unread.',
                   'Descriptor grant bits describe configured policy; they do not prove current effective permission or a successful read of another region.',
                   'Configured density is not independent component identity or measured capacity.',
                   'A backup file, even if later completed, would not establish remote recovery after failed POST.']
    output=HERE/f'hardware_descriptor{version}.json'
    output.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':out['status'],'output':str(output),'sha256':sha(output),'decoded':out['decoded']},ensure_ascii=False))

if __name__=='__main__':main()
