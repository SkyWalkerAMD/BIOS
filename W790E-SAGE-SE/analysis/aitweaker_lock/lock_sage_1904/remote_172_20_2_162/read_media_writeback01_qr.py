"""Recover disposable-file test evidence; local image reopen remains required."""
from pathlib import Path
import hashlib,importlib.util,json,re,sys
HERE=Path(__file__).resolve().parent
path=HERE.parents[1]/'probe_p3_kvm/decode_captures.py'
spec=importlib.util.spec_from_file_location('p3_decoder',path)
decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)

def parse_log(raw):
    if not raw.startswith(b'MEDIA-WRITEBACK-01 DISPOSABLE TEST FILE ONLY\r\n') or not raw.endswith(b'PROBE_COMPLETE\r\n'):
        raise ValueError('Unexpected diagnostic identity')
    text=raw.decode('ascii')
    def field(name):
        found=re.findall(r'^'+re.escape(name)+r'=0x([0-9A-F]+)\r?$',text,re.M)
        if len(found)!=1:raise ValueError('Missing or duplicate '+name)
        return int(found[0],16)
    if field('EXPECTED_FILE_BYTES')!=120 or field('EXPECTED_FILE_CRC32')!=0x2dc67546:
        raise ValueError('File contract changed')
    status=field('TEST_STATUS')
    if not status:
        for name,value in [('Watchdog.disable',0),('CONNECT_USB_STORAGE_STATUS',0),
                           ('EXACT_MATCHES',1),('ENUMERATION_UNCERTAIN',0),
                           ('FILE_WRITE_STATUS',0),('FILE_WRITE_BYTES',120),
                           ('FILE_FLUSH_STATUS',0),('FILE_CLOSE_STATUS',0),('UEFI_FILE_READBACK_STATUS',0)]:
            if field(name)!=value:raise ValueError('Success invariant '+name)
    return {'status':'UEFI_FILE_TEST_PASSED_REQUIRES_HOST_IMAGE_REOPEN' if not status else 'FILE_TEST_REFUSED_OR_FAILED',
            'efi_status':hex(status),'expected_file_bytes':120,'expected_file_crc32':'2DC67546',
            'complete_spi_backup':False,'permanent_password_lock_test':False}

def main():
    if sys.argv[1]=='frame':
        screenshot=Path(sys.argv[2]);raw=decoder.read_image(screenshot);frame=decoder.parse_frame(raw)
        screenshot.with_suffix('.frame').write_bytes(raw)
        print(json.dumps({k:v for k,v in frame.items() if k!='data'}))
    elif sys.argv[1]=='assemble':
        folder=Path(sys.argv[2]);raw,meta=decoder.assemble([p.read_bytes() for p in sorted(folder.glob('*.frame'))],require_inventory=False)
        result=parse_log(raw);target=folder/'hardware-log.txt'
        if target.exists() and target.read_bytes()!=raw:raise FileExistsError(target)
        target.write_bytes(raw);meta['capture']=result
        meta['scope']='Disposable 120-byte file diagnostic only; reopen local image independently after session closure.'
        meta['files']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.glob('*')) if p.is_file() and p.name!='manifest.json'}
        (folder/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(meta))
    else:raise ValueError('Unsupported action')
if __name__=='__main__':main()
