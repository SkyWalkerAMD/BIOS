"""Decode existing P3 QR frames, enforce this probe's complete-log contract."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2]
decoder=CASE.parent/'probe_p3_kvm/decode_captures.py'
spec=importlib.util.spec_from_file_location('p3_decode',decoder);p3=importlib.util.module_from_spec(spec);spec.loader.exec_module(p3)
def decode(paths):
    data,meta=p3.assemble([p3.read_image(p)for p in paths],require_inventory=False)
    if not data.startswith(b'AITWK-P3-KVM\r\nSAGE_NATIVE13_ENTRY_CONTEXT03_READONLY\r\n'):raise ValueError('Different log type')
    required=[b'LOG_OVERFLOW=NO\r\n',b'LOG_COMPLETE=YES\r\n',b'INSTALLER_PRESENT=NO\r\n',b'INSTALLATION_AUTHORIZED_BY_PROBE=NO\r\n',b'RuntimeTableChanged=NO\r\n',b'ProviderStarted=NO\r\n',b'NO_FLASH_NO_HOOKS_NO_VARIABLE_WRITES_NO_DISK_WRITES\r\n']
    if any(x not in data for x in required)or not data.endswith(b'SAGE_NATIVE13_ENTRY_CONTEXT03_END\r\n')or b'LOG_OVERFLOW=YES'in data:raise ValueError('Missing footer, truncated or incomplete diagnostic log')
    if len(data)>24575:raise ValueError('Exceeds this probe log bound')
    return data,meta
def main():
    p=argparse.ArgumentParser();p.add_argument('screenshots',nargs='+');p.add_argument('--output',required=True);a=p.parse_args();paths=[]
    for item in a.screenshots:
        path=Path(item);paths+=sorted(path.glob('qr-*.png'))if path.is_dir()else[path]
    data,meta=decode(paths);dest=Path(a.output)
    if dest.exists()and dest.read_bytes()!=data:raise FileExistsError('Refusing overwrite of different evidence')
    if not dest.exists():dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
    print(json.dumps({'output':str(dest),**meta,'read_only_footer_verified':True},indent=2))
if __name__=='__main__':main()
