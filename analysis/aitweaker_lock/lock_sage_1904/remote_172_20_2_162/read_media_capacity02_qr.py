"""Transport-only P3 capacity capture; semantic validation is separate."""
from pathlib import Path
import hashlib, importlib.util, json, sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent/'review/flash_readiness/remote_only/media_capacity_candidate02'

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    obj=importlib.util.module_from_spec(spec);sys.modules[name]=obj;spec.loader.exec_module(obj)
    return obj

decoder=module('capacity02_p3_decoder',HERE.parents[1]/'probe_p3_kvm/decode_captures.py')

def main():
    if sys.argv[1]=='frame':
        screenshot=Path(sys.argv[2]);raw=decoder.read_image(screenshot)
        info=decoder.parse_frame(raw)
        if info['pages']>64 or info['total']>=32768:raise ValueError('Capture limit exceeded')
        screenshot.with_suffix('.frame').write_bytes(raw)
        print(json.dumps({k:v for k,v in info.items() if k!='data'}))
    elif sys.argv[1]=='assemble':
        folder=Path(sys.argv[2])
        raw,meta=decoder.assemble([p.read_bytes() for p in sorted(folder.glob('*.frame'))],require_inventory=False)
        head=b'MEDIA-CAPACITY-02 STANDARD SCSI OWNER ONLY\r\n'
        footer=(b'FILE_OPS=0 BLOCK_DATA_OPS=0 RAW_USB_OPS=0 CONNECT_OPS=0\r\n'
                b'SCSI_WRITE_OPS=0 SCSI_RESET_OPS=0 PASSTHRU_COMMANDS=0 RUNTIME_OPS=0\r\n'
                b'PROBE_COMPLETE\r\n')
        if len(raw)>=32768 or not raw.startswith(head) or raw.count(footer)!=1 or not raw.endswith(footer):
            raise ValueError('Probe identity or operation footer mismatch')
        target=folder/'hardware-log.txt'
        if target.exists() and target.read_bytes()!=raw:raise FileExistsError(target)
        target.write_bytes(raw)
        meta['scope']='P3 transport verified; no inference of capacity success, disk writeback or BIOS acceptance.'
        meta['semantic_parse_pending']=True
        meta['files']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.glob('*'))
                       if p.is_file() and p.name!='manifest.json'}
        (folder/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf8')
        print(json.dumps(meta))
    else:raise ValueError('Unsupported action')

if __name__=='__main__':main()
