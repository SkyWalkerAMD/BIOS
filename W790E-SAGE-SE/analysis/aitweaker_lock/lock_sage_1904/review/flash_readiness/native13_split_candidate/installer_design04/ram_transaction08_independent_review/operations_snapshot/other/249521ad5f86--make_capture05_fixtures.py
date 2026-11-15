from pathlib import Path
import importlib.util,json,sys,zlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6]
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
import zxingcpp
from PIL import Image
OUT=HERE/'capture05-qr-fixtures';OUT.mkdir(exist_ok=True)
for sid in [7,8]:
    raw=b'AITWK-P3-KVM\r\nSAGE_NATIVE13_RAM_TEST05\r\n'+f'SNAPSHOT_ID={sid:016X}\r\n'.encode()+b'LOCAL_TEST_DATA_ONLY=YES\r\n'*70+b'LOG_COMPLETE=YES\r\nLOG_OVERFLOW=NO\r\nSAGE_NATIVE13_RAM_TEST05_END\r\n'
    total=len(raw);pages=(total+767)//768
    for i in range(pages):
        part=raw[i*768:(i+1)*768]
        frame=f'AITWK-P3-KVM\nT={total};C={zlib.crc32(raw):08X};P={i+1}/{pages};O={i*768};N={len(part)};D={zlib.crc32(part):08X}\n\n'.encode()+part
        bmp=zxingcpp.write_barcode(zxingcpp.BarcodeFormat.QRCode,frame,width=720,height=720)
        view=memoryview(bmp);Image.frombytes('L',(view.shape[1],view.shape[0]),view.tobytes()).save(OUT/f'snapshot-{sid}-page-{i+1}.png')
    (OUT/f'snapshot-{sid}.txt').write_bytes(raw)
print(json.dumps({'local_synthetic_QR_only':True,'output':str(OUT),'pages_each':pages}))
