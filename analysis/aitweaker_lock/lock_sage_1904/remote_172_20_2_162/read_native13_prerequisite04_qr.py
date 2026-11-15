"""Capture N13 prerequisite logs. Owned RAM may change; original firmware may not."""
from pathlib import Path
import hashlib, importlib.util, json, re, sys
HERE=Path(__file__).resolve().parent
p3path=HERE.parents[1]/'probe_p3_kvm/decode_captures.py'
if hashlib.sha256(p3path.read_bytes()).hexdigest()!='f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283':
    raise ValueError('P3 decoder binding changed')
spec=importlib.util.spec_from_file_location('native13_prerequisite04_p3',p3path)
decoder=importlib.util.module_from_spec(spec);sys.modules[spec.name]=decoder;spec.loader.exec_module(decoder)

def main():
    if len(sys.argv)!=3:raise ValueError('Expected frame or assemble and one path')
    if sys.argv[1]=='frame':
        screenshot=Path(sys.argv[2]);raw=decoder.read_image(screenshot);info=decoder.parse_frame(raw)
        if info['pages']>64 or info['total']>=24576:raise ValueError('Capture limit exceeded')
        screenshot.with_suffix('.frame').write_bytes(raw)
        print(json.dumps({k:v for k,v in info.items() if k!='data'}))
    elif sys.argv[1]=='assemble':
        folder=Path(sys.argv[2]);raw,meta=decoder.assemble([p.read_bytes() for p in sorted(folder.glob('*.frame'))],require_inventory=False)
        if len(raw)>=24576 or not raw.startswith(b'AITWK-P3-KVM\r\nSAGE_NATIVE13_PREREQUISITE04_OWNED_ONLY\r\n') or not raw.endswith(b'SAGE_NATIVE13_PREREQUISITE04_END\r\n'):
            raise ValueError('Probe identity or length mismatch')
        required=[b'INSTALLER_PRESENT=NO',b'INSTALLATION_AUTHORIZED_BY_PROBE=NO',b'RuntimeTableChanged=NO',b'ProviderStarted=NO',b'LOG_COMPLETE=YES',b'LOG_OVERFLOW=NO',b'BROWSER_ABSENCE_PROOF=NO']
        if any(raw.count(x)!=1 for x in required):raise ValueError('Scope or completeness marker mismatch')
        if raw.count(b'NO_FLASH_NO_HOOKS_NO_VARIABLE_WRITES_NO_DISK_WRITES')!=2:raise ValueError('Scope count mismatch')
        observed={}
        if b'PREREQUISITE04_BEGIN\r\n' in raw:
            for key in [b'FOREIGN_PAGE_ATTRIBUTES_REQUESTED=NO',b'ORIGINAL_MODULE_BYTES_WRITTEN=NO']:
                if raw.count(key)!=1:raise ValueError('Original-memory scope marker mismatch')
            for key in ['RetainedOwnedPages','EBSObserved','ResidentHoldRequired']:
                values=re.findall(rb'(?m)^'+key.encode()+rb'=([0-9A-Fa-f]{16})\r?$',raw)
                if len(values)!=1:raise ValueError('Missing owned-RAM completion state')
                observed[key]=int(values[0],16)
        target=folder/'hardware-log.txt'
        if target.exists() and target.read_bytes()!=raw:raise FileExistsError(target)
        target.write_bytes(raw)
        meta.update(scope='Transport and scope markers only. Probe may modify and restore its own allocated RAM. No native hook installation or flash acceptance.',semantic_parse_pending=True,owned_completion_fields=observed)
        meta['files']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.iterdir()) if p.is_file() and p.name!='manifest.json'}
        (folder/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf-8');print(json.dumps(meta))
    else:raise ValueError('Unsupported action')
if __name__=='__main__':main()
