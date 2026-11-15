"""Independently decode all I2c PNGs and compare bytes/fingerprints offline."""
from pathlib import Path
import importlib.util,json,hashlib,zlib
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
tool=ROOT/'analysis/hero_fw_i2c_20261108/decode_captures.py'
spec=importlib.util.spec_from_file_location('i2c_live_decoder',tool);decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
capture=ROOT/'analysis/hero_ipmi_continued_live_20261108/captures/hero71-fv-sections-i2c'
txt=ROOT/'analysis/hero_ipmi_continued_live_20261108/hero71-fv-sections-i2c.TXT'
frames=[];screens=[]
for image in sorted(capture.glob('*.png')):
 frame=decoder.read_image(image);stored=image.with_suffix('.qr.bin').read_bytes();assert frame==stored
 parsed=decoder.parse_frame(frame);frames.append(frame)
 screens.append(dict(page=parsed['page'],png_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),stored_frame_exact=True))
body,meta=decoder.assemble(frames);assert body==txt.read_bytes()
assert meta==dict(pages=18,bytes=8732,crc32='A1289794',sha256='f4527e2535b3f2232439a1107ad07b5c431a32b5b535c8d96998ab469672d4bf')
rows=[];current=None;identity=[];file_target=None
for line in body.decode('ascii').splitlines():
 if line.startswith('SC_TARGET='):
  current=dict(target=line.split('=',1)[1]);rows.append(current)
 elif current is not None and line.startswith('SC_'):
  k,v=line.split('=',1);current[k[3:].lower()]=v if k=='SC_MODE' else int(v,16)
 if line.startswith('FP_FV_TARGET='):file_target=line.split('=',1)[1]
 if line.startswith('FP_FV_BODY_CRC32='):identity.append(dict(target=file_target,body_crc32=line.split('=',1)[1][-8:]))
 if line.startswith('FP_FV_PE_CRC32='):identity[-1]['pe_crc32']=line.split('=',1)[1][-8:]
assert len(rows)==8
assert {(r['target'],r['type'],r['mode']) for r in rows}=={(t,k,m) for t in ['R2','P5_P6'] for k in [0x13,0x10] for m in ['AUTOALLOC','PREALLOC']}
assert all(r['status']==0x8000000000000002 and r['exact_match']==0 for r in rows)
assert all(r['buffer']==0 and r['bytes']==0 for r in rows if r['mode']=='AUTOALLOC')
assert all(r['buffer'] and r['bytes']==r['expected_bytes'] for r in rows if r['mode']=='PREALLOC')
expected={('R2',0x13):(36,0xC165A0D6),('R2',0x10):(22016,0x1D66102E),('P5_P6',0x13):(54,0x532E5690),('P5_P6',0x10):(371712,0xBDB6FE43)}
assert all((r['expected_bytes'],r['expected_crc32'])==expected[(r['target'],r['type'])] for r in rows)
assert identity==[dict(target='R2',body_crc32='C1E922F8',pe_crc32='1D66102E'),dict(target='P5_P6',body_crc32='8346283A',pe_crc32='BDB6FE43')]
result=dict(capture=meta,pngs_decoded=len(screens),all_pngs_equal_saved_qr_frames=True,whole_crc_and_txt_exact=True,rows=rows,readfile_identity=identity,all_readsection_status='EFI_INVALID_PARAMETER',buffer_mode_does_not_resolve_failure=True,automatic_allocations_returned=0,diagnostic_complete_is_not_readsection_success=True,screens=screens)
(P/'i2c-live-validation.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ['rows','screens']},indent=2))
