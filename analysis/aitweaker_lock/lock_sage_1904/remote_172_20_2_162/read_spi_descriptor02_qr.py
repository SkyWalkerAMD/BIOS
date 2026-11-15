"""Recover FD02 evidence; distinguish descriptor capture from complete backup."""
from pathlib import Path
import hashlib,importlib.util,json,re,struct,sys
HERE=Path(__file__).resolve().parent
path=HERE.parents[1]/'probe_p3_kvm/decode_captures.py'
spec=importlib.util.spec_from_file_location('p3_decoder',path)
decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)

def parse_descriptor(raw):
    if not raw.startswith(b'SPI-DESCRIPTOR-02 LOCAL-CANDIDATE\r\n') or not raw.endswith(b'PROBE_COMPLETE\r\n'):
        raise ValueError('Unexpected diagnostic identity')
    text=raw.decode('ascii')
    def field(name):
        found=re.findall(r'^'+re.escape(name)+r'=0x([0-9A-F]+)\r?$',text,re.M)
        if len(found)!=1:raise ValueError('Missing or duplicate field '+name)
        return int(found[0],16)
    status=field('CAPTURE_STATUS')
    if status:
        if 'DESCRIPTOR_HEX_BEGIN' in text or 'DESCRIPTOR_TWO_PASSES_MATCH=YES' in text:
            raise ValueError('Failure incorrectly exports descriptor')
        return None,{'status':'CAPTURE_REFUSED_OR_FAILED','efi_status':hex(status),'failure_stage':field('FAILURE_STAGE'),
                     'mmio_write_calls':field('ACTUAL_MMIO_WRITE_CALLS'),'read_cycle_start_attempts':field('READ_CYCLE_START_ATTEMPTS')}
    for key,expected in [('READ_CYCLE_START_ATTEMPTS',128),('COMPLETED_BLOCKS',128),('COMPLETED_PASSES',2),
                         ('TRANSIENT_FIELDS_RESTORED',1),('PROTECTION_SNAPSHOT_UNCHANGED',1),('FAILURE_STAGE',0)]:
        if field(key)!=expected:raise ValueError('Capture invariant '+key)
    if not 128<=field('POLL_OBSERVATIONS')<=1280000:raise ValueError('Poll count bound')
    if not 0<=field('EXACT_BUSY_FGO_OBSERVATIONS')<field('POLL_OBSERVATIONS'):raise ValueError('Busy FGO count bound')
    if text.count('DESCRIPTOR_TWO_PASSES_MATCH=YES\r\n')!=1:raise ValueError('No unique pass comparison')
    if text.count('DESCRIPTOR_HEX_BEGIN\r\n')!=1 or text.count('DESCRIPTOR_HEX_END\r\n')!=1:raise ValueError('Invalid descriptor boundaries')
    blob=text.split('DESCRIPTOR_HEX_BEGIN\r\n',1)[1].split('DESCRIPTOR_HEX_END\r\n',1)[0]
    rows=blob.splitlines()
    if len(rows)!=128:raise ValueError('Descriptor row count')
    out=bytearray()
    for i,line in enumerate(rows):
        match=re.fullmatch(r'([0-9A-F]{4}):([0-9A-F]{64})',line)
        if not match or int(match[1],16)!=i*32:raise ValueError('Descriptor row address/format')
        out.extend(bytes.fromhex(match[2]))
    if len(out)!=4096 or struct.unpack_from('<I',out,0x10)[0]!=0x0ff0a55a:raise ValueError('Descriptor size/signature')
    return bytes(out),{'status':'DESCRIPTOR_4K_CAPTURED_TWO_PASSES_MATCH','bytes':len(out),'sha256':hashlib.sha256(out).hexdigest(),
                       'mmio_write_calls':field('ACTUAL_MMIO_WRITE_CALLS'),'read_cycle_start_attempts':128,
                       'complete_spi_backup':False,'flash_programming_or_erase':False}

def main():
    if sys.argv[1]=='frame':
        screenshot=Path(sys.argv[2]);raw=decoder.read_image(screenshot);frame=decoder.parse_frame(raw)
        screenshot.with_suffix('.frame').write_bytes(raw)
        print(json.dumps({k:v for k,v in frame.items() if k!='data'}))
    elif sys.argv[1]=='assemble':
        folder=Path(sys.argv[2]);raw,meta=decoder.assemble([p.read_bytes() for p in sorted(folder.glob('*.frame'))],require_inventory=False)
        descriptor,capture=parse_descriptor(raw)
        for name,data in [('hardware-log.txt',raw)]+([('hardware-descriptor.bin',descriptor)] if descriptor is not None else []):
            target=folder/name
            if target.exists() and target.read_bytes()!=data:raise FileExistsError(target)
            target.write_bytes(data)
        meta['capture']=capture
        meta['scope']='Physical descriptor-read diagnostic; only 4 KiB, not a complete SPI backup or recovery proof.'
        meta['files']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.glob('*')) if p.is_file() and p.name!='manifest.json'}
        (folder/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(meta))
    else:raise ValueError('Unsupported action')
if __name__=='__main__':main()
