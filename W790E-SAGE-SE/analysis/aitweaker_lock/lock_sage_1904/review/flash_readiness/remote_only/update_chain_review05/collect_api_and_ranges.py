"""Resolve native route descriptors, frontend flow, and original NPB metadata."""
from pathlib import Path
import json,re,struct,sys
sys.dont_write_bytecode=True
from inspect_chain import HERE,BASE,ROOT,Elf32,FILES,sha,disassemble
def artifact(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}
def main():
    rest=Elf32(FILES['rest']);routes=[]
    wanted=['VerifySignature_data','uploadBIOSSignature_data','GetFeatureList_data','getBmcFeature_data','putBIOSStartFlashMode_data','BIOSVerifyImage_data','setBIOSPrepareComponents_data']
    for name in wanted:
        sym=next((s for s in rest.symbols if s['name']==name and s['section_index']),None)
        if not sym:continue
        row={'symbol':sym,'fields':[]}
        for i in range(0,sym['size'],4):row['fields'].append({'offset':hex(i),**rest.literal(sym['va']+i)})
        refs=[]
        for m in re.finditer(re.escape(struct.pack('<I',sym['va'])),rest.data):
            va=next((s['va']+m.start()-s['offset'] for s in rest.sections if s['type']!=8 and s['offset']<=m.start()<s['offset']+s['size']),0)
            if va>=rest.byname['.data']['va']:
                refs.append({'pointer_va':hex(va),'neighborhood':[rest.literal(p) for p in range(va-20,va+24,4)]})
        row['data_references']=refs;routes.append(row)
    strings=[]
    for m in re.finditer(rb'/api/[\x20-\x7e]+',rest.data):
        text=m.group().decode();
        if 'feature' in text.lower():strings.append({'path':text,'offset':hex(m.start())})
    js=BASE.parent/'bmc/20261103T012222229717Z/selected_modules/views_maintenance_BIOSUpdateView.js'
    source=js.read_text();methods={}
    for method in ['EntryUpdateMode','PrepareComponents','UploadSignature','VerifySignature','UploadBIOS','GetBIOSInfo','FlashBIOS','VerifyBIOS','ExitUpdateMode']:
        start=source.index(method+':function');left=source.index('{',start);depth=0;quote=None;escape=False
        for i in range(left,len(source)):
            c=source[i]
            if quote:
                if escape:escape=False
                elif c=='\\':escape=True
                elif c==quote:quote=None
            elif c in ('"',"'"):quote=c
            elif c=='{':depth+=1
            elif c=='}':
                depth-=1
                if not depth:methods[method]=source[start:i+1];break
    cap=ROOT/'analysis/aitweaker_lock/official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
    raw=cap.read_bytes();require_hash='aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3';assert sha(raw)==require_hash
    payload=raw[4096:];headers=[]
    for m in re.finditer(re.escape(b'$BOOTEFI$'),payload):
        off=m.start()
        if not 0x3000000<=off<0x4000000:continue
        h=payload[off:off+0xcb];u32=lambda d:struct.unpack_from('<I',h,d)[0]
        record={'offset':hex(off),'sha256':sha(h),'bytes':h.hex(),'major_version_0c':h[12],'minor_version_0d':h[13],'marker0f':h[15],
                'size_at75':hex(u32(0x75)),'NPB_count_atBB':u32(0xbb),'NPB_relative_atBF':hex(u32(0xbf)),'records':[]}
        # Exact arithmetic in PDK_GetASUSBIOSInfo for 64MiB input scan at 48MiB.
        if u32(0xbf) and u32(0xbb)<=128:
            pos=(u32(0xbf)+u32(0x75)+(0x3000000 if u32(0x75)==0x1000000 else 0))&0xffffffff
            record['NPB_table_offset']=hex(pos)
            for i in range(u32(0xbb)):
                if pos+i*9+9>len(payload):record['bounds_error']=True;break
                data=payload[pos+i*9:pos+(i+1)*9];flag,address,length=struct.unpack('<BII',data)
                record['records'].append({'index':i,'flag':flag,'offset':hex(address),'bytes':length,'end_exclusive':hex(address+length),'raw':data.hex()})
        headers.append(record)
    out={'rest':artifact(FILES['rest']),'route_descriptors':routes,'feature_route_strings':strings,'frontend':artifact(js),'frontend_methods':methods,
         'original_cap':artifact(cap),'original_staged_payload_bytes':len(payload),'original_BOOTEFi_headers':headers,
         'interpretation_limit':'BiosConfiguration passes current-MTD header as argument4 (major/minor both zero skips preservation), and uploaded-image header as argument5 (NPB count/list). Thus uploaded CAP supplies the listed ranges; current hardware header/gate, complete source reads and final staged bytes have not been observed.'}
    (HERE/'api_and_ranges.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
    bios=Elf32(FILES['bios'])
    spec={'status':'OFFLINE_FIXED_CANDIDATE_PAGE_SPEC_NOT_A_LIVE_LOCATION_CLAIM','original_cap':artifact(cap),
          'candidate_spi_page':{'offset':'0x03ecc000','bytes':4096,'original_page_sha256':sha(payload[0x3ecc000:0x3ecd000]),'region':'descriptor BIOS region1','expected_header_offset':'0x03eccda4','header_bytes':203,'header_end_exclusive':'0x03ecce6f','expected_table_offset':'0x03eccd70','table_bytes':36},
          'source_header':headers[0],'field_meanings':{'0x00':'$BOOTEFI$ nine-byte signature','0x09':'StructVersion (original9)','0x0c':'MajorVersion','0x0d':'MinorVersion','0x0e':'BaseboardId,30 bytes','0x75':'ImageSize,u32LE','0xbb':'NonProgramBlockCount,u32LE','0xbf':'NonProgramBlockTableOffset,u32LE; original value is negative relative to image size modulo2^32'},
          'field_label_literal_evidence':[bios.literal(p) for p in [0x2cb4,0x2cc0,0x2cc4,0x2cc8]],
          'configuration_argument_evidence':[bios.literal(p) for p in [0x3c2c,0x3c30,0x3c34,0x3c38]],
          'preservation_gate':'PDK_ASUSBIOSConfiguration checks argument4 header major/minor; bothzero returns0 without copying. Native normal/force decision is SECTION_FLASH==0xff skips wholeBiosConfiguration. NPB itself comes from argument5 uploaded header.',
          'probe_constraints':['Only separately authorized fixed4KiB BIOSregion read; preserve already-reviewed descriptor/identity/SCIP/transaction gates.','Read twice and compare; never change permission/protection/GPIO/ownership.','Missing magic/model/version/size or unexpected bounds is UNKNOWN; do not silently scan other addresses or region9.','Do not promote officialCAP address to proven live location: current OEM fullimage differs. The vendor parser searches full16MiB BIOS region in2KiB chunks; this fixedprobe deliberately does not.'],
          'does_not_prove':['Live g_corefeatures resident-key flag','Backup/export/recovery','Full image identity or all NPB source read reliability','Authorization to upload/prepare/flash']}
    (HERE/'bios_header_read_spec.json').write_text(json.dumps(spec,indent=2),encoding='utf-8')
    for name in ['host','pdk']:
        path=BASE/'bmc_backend/5308416/usr/local/lib'/('libhosthelper.so.13.0.1' if name=='host' else 'libpdkapp.so.13.2.4');elf=Elf32(path)
        pats='flash_bios_image|verify_bios_img|spi_write_erase_block' if name=='host' else 'PDK_ASUSBIOSConfiguration|read_file_append|PDK_GetASUSBIOSInfo'
        for sym in elf.symbols:
            if sym['section_index'] and (sym['info']&15)==2 and re.search(pats,sym['name']):
                rep,text=disassemble(elf,sym);p=HERE/'disassembly'/name;p.mkdir(exist_ok=True,parents=True)
                (p/(sym['name']+'.txt')).write_text(text,encoding='utf-8')
    print(json.dumps({'feature_routes':strings,'headers':headers,'route_names':[x['symbol']['name'] for x in routes]},indent=2))
if __name__=='__main__':main()
