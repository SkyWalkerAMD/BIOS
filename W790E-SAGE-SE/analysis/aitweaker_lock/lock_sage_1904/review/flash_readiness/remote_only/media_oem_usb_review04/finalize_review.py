"""Freeze this bounded original-ASUS review; never edits any prior artifacts."""
from pathlib import Path
import hashlib,json,lzma,re,struct,sys,uuid
from datetime import datetime,timezone
from locate_module import HERE,ROOT,CAP,EXPECTED
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64

def digest(p):
    b=p.read_bytes();return {'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

def main():
    cap=CAP.read_bytes();assert hashlib.sha256(cap).hexdigest()==EXPECTED
    sec=0x3181078+24;n=int.from_bytes(cap[sec:sec+3],'little')
    raw=lzma.decompress(cap[sec+24:sec+n],format=lzma.FORMAT_ALONE)
    assert hashlib.sha256(raw).hexdigest()=='88067e05d84ed3157eb34964217a5baaba094ed2c1d7d67ab76583bee9a77a9b'
    rows=[]
    for guid,label,ranges in [
        ('580DD900-385D-11D7-883A-00500473D4EB','Uhcd',[(0x995c,0x9ce8),(0x9e70,0xa2d4)]),
        ('171F43DC-C4D9-47A6-9641-65DDCDD5AA30','UsbRtDxe',[(0x9bd0,0x9d58)]),
        ('04EAAAA1-29A1-11D7-8838-00500473D4EB','UsbRtSmm',[(0xb1b4,0xb33c)])]:
        file=HERE/(guid+'.efi');data=file.read_bytes();off=raw.find(data)
        assert off>=0 and raw.find(data,off+1)<0
        ffs=raw.rfind(uuid.UUID(guid).bytes_le,max(0,off-128),off)
        assert ffs>=0
        ffsbytes=int.from_bytes(raw[ffs+20:ffs+23],'little');assert ffs<=off and off+len(data)<=ffs+ffsbytes
        pe=pefile.PE(data=data);md=Cs(CS_ARCH_X86,CS_MODE_64)
        code=[]
        for start,end in ranges:
            binary=pe.get_data(start,end-start)
            code.append({'start_rva':hex(start),'end_rva':hex(end),'sha256':hashlib.sha256(binary).hexdigest(),
                         'instructions':[{'rva':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in md.disasm(binary,start)]})
        (HERE/(label+'_geometry_instructions.json')).write_text(json.dumps(code,indent=2),encoding='utf8')
        rows.append({'name':label,'naming_source':'existing local UEFITool GUID catalogue; behavioral identity independently checked via protocol/commands',
                     'guid':guid,'EFI':digest(file),'PE_offset_in_decompressed_CAP':hex(off),'FFS_offset_in_decompressed_CAP':hex(ffs),'FFS_bytes':ffsbytes,
                     'direct_original_CAP_match':True,'reviewed_ranges':[{k:v for k,v in c.items() if k!='instructions'} for c in code]})
    report={
      'status':'BOUNDED_ORIGINAL_UEFI_REVIEW_COMPLETE_ROOT_CAUSE_UNRESOLVED',
      'created_utc':datetime.now(timezone.utc).isoformat(),
      'scope':'Only original SAGE SE1904 Uhcd, UsbRtDxe and UsbRtSmm capacity parser/publication paths. Static Ghidra/Capstone and synthetic Unicorn; no device/network/rawUSB/SMI operation. No production client or existing artifact changed.',
      'original_CAP':digest(CAP),'decompressed_container_sha256':hashlib.sha256(raw).hexdigest(),'modules':rows,
      'confirmed':[
        {'kind':'actual original bytes / local replay','finding':'UsbRtDxe RVA0x9BD0 and UsbRtSmm RVA0xB1B4 issue READ CAPACITY(10), parse BE response data, store uint16 blockSize atDEV_INFO+0x5E and lastLBA+1 atDEV_INFO+0x60. The normal00007fff00000200 response becomes512/32768 in both modules.',
         'evidence':['usbrtdxe_decompile/00009bd0-FUN_00009bd0.c','usbrtsmm_decompile/0000b1b4-FUN_0000b1b4.c','oem_geometry_replay.json']},
        {'kind':'actual original bytes / local replay','finding':'Uhcd RVA0x995C creates BlockIO media with BlockSize=DEV_INFO+0x5E and LastBlock=(DEV_INFO+0x60)-1. It marks present only when bit0 ofDEV_INFO+0xA0, nonzero totalBlocks and nonzero blockSize are present. Missing flags or zero geometry produce LastBlock0/mediaPresent0.',
         'evidence':['uhcd_decompile/0000995c-FUN_0000995c.c','Uhcd_geometry_instructions.json','oem_geometry_replay.json']},
        {'kind':'static original bytes','finding':'The BlockIO refresh path Uhcd RVA0x9E70 also updates BlockSize and LastBlock from the same DEV_INFO fields. No extra shift, doubling or byte-order change is present in the inspected publication/refresh arithmetic.',
         'evidence':['uhcd_decompile/00009e70-FUN_00009e70.c','Uhcd_geometry_instructions.json']},
        {'kind':'actual original bytes / local replay','finding':'Both local RC10 parser functions return low8=0xFF without clearing existing DEV_INFO geometry on transport failure, zero blocksize or inactive device flags. Synthetic prior1024/262145 survives; initial zero stays zero. This is preservation, not a hard-coded default.',
         'evidence':['oem_geometry_replay.json']},
        {'kind':'static scope-limited finding','finding':'No fixed1024/0x40000 geometry fallback occurs in the reviewed RC10/publication paths. The initialization wrappers retry RC10 and may issue READ FORMAT CAPACITIES(0x23) for specific sense conditions; their0x40000 occurrence is a flag test, not a capacity assignment.',
         'evidence':['usbrtdxe_decompile/0000a4b8-FUN_0000a4b8.c','usbrtdxe_decompile/00009d58-FUN_00009d58.c','usbrtsmm_decompile/0000ba9c-FUN_0000ba9c.c','usbrtsmm_decompile/0000b33c-FUN_0000b33c.c']}
      ],
      'inferences_and_limits':[
        'The ordinary original UEFI path does not transform a correct16MiB/512 response into observed1024/LastBlock0x40000. The observed geometry can be published when DEV_INFO already contains1024/262145, but where those values came from remains unknown.',
        'A stale-data explanation is conditional only. Whole DEV_INFO allocation/lifetime, all initialization failure branches, active DXE-versus-SMM routing and exact on-device bytes were not dynamically measured. Do not claim a firmware bug or actual stale state.',
        'Synthetic transport fills in-memory data and never calls USB. Synthetic runtime dispatch replaces the SMI path. Synthetic BootServices does not publish any real protocol.',
        'Public originalCAP matches extracted modules byte-for-byte, but firmware loaded in the current machine was not read back and individually fingerprinted in this subtask.'
      ],
      'next_smallest_observation':{
        'primary':'After a separately reviewed diagnostic is prepared, capture raw READ CAPACITY(10) data and current BlockIO fields on only the identified046B:FF31 USB mass-storage interface. Do not perform it as part of this offline review.',
        'outcomes':[
          {'raw_RC10':'00007fff00000200','BlockIO':'1024/0x40000','implication':'Narrows discrepancy to UEFI cached DEV_INFO/selected interface/routing or later update; backend visible capacity itself is correct at observation time.'},
          {'raw_RC10':'0004000000000400','BlockIO':'1024/0x40000','implication':'Narrows to actual backing device/backend/gadget state, not ordinary UEFI RC10 arithmetic.'},
          {'raw_RC10':'command error / stalled / short reply','BlockIO':'nonzero old geometry','implication':'Shows command failure alongside cached metadata, but still requires lifecycle evidence to establish when cache became stale.'}
        ],
        'secondary':'If an already-authorized read-only BMC diagnostic interface exposes active NBD size/logical_block_size and gadget LUN file, compare those with the raw result. Do not change BMC settings or bypass unavailable interfaces.',
        'constraints':'No rawUSB operation has been designed, deployed or performed here. Keep existing WB geometry, label and marker gates; do not enlarge the fixed image or spoof capacity to obtain a pass.'
      },
      'validation':{'actual_original_x64_cases':17,'DXE_RC10':6,'SMM_RC10':6,'Uhcd_publication':5,'status':'PASS',
                    'fixture_adjustment':'Initial synthetic publication fixture missed the controller pointer-array indirection and faulted atRVA0x9C53. Corrected only synthetic object wiring; original EFI bytes remained unchanged.'}
    }
    (HERE/'oem_geometry_review.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    artifacts=[]
    for p in sorted(HERE.rglob('*')):
        if not p.is_file() or p.name=='manifest.json':continue
        rel=p.relative_to(HERE)
        if any(part.startswith('ghidra') for part in rel.parts):
            if not (p.name.endswith('.argv.json') or p.name.endswith('.stdout.log') or p.name in ['analysis.log','script.log','selection.txt']):continue
        artifacts.append(digest(p))
    inputs=[digest(ROOT/'analysis/uefitool_guids.csv'),digest(HERE.parent/'BmcSelectedDecompile.java'),digest(HERE.parent/'media_geometry_review03/geometry_review.json'),digest(HERE.parent/'media_geometry_review03/manifest.json')]
    manifest={'status':report['status'],'files':artifacts,'read_only_inputs':inputs}
    (HERE/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    print(json.dumps({'report':digest(HERE/'oem_geometry_review.json'),'manifest':digest(HERE/'manifest.json'),'artifacts':len(artifacts)}))
if __name__=='__main__':main()
