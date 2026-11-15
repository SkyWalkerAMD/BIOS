"""Independent original-PNG decode; frozen entry probe is never modified."""
from pathlib import Path
import hashlib,json,re,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];OLD=HERE/'entry_probe';CAP=CASE/'remote_172_20_2_162/hardware-native13-entry-1793696498298'
sys.dont_write_bytecode=True;sys.path.insert(0,str(OLD));from decode_probe import decode
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=OLD/'entry_context_manifest.json';mh=sha(manifest)
for a in json.loads(manifest.read_text())['artifacts']:assert sha(HERE/a['path'])==a['sha256'],a['path']
images=[CAP/f'page-{i:02}.png'for i in range(1,9)];data,meta=decode(images)
assert len(data)==5726 and meta['crc32']=='F0CA537A'and meta['sha256']=='5afe0c3adb224f8a25627c15766d99a5cc29ad7c8eaa9fa3df231b1eef9faf12'
assert data==(CAP/'hardware-log.txt').read_bytes();out=HERE/'entry_hardware_review';out.mkdir(exist_ok=True);(out/'independently-decoded.log').write_bytes(data)
text=data.decode('ascii');core=text.split('CONTEXT_MODULE DxeCore\r\n',1)[1].split('CONTEXT_MODULE BdsArch',1)[0]
assert'ContextModuleCount=0000000000000001'in core and'ContextModuleBase=0000000054F69000'in core and'ContextModuleSize=0000000000021000'in core
assert'normalized complete text SHA256'not in core and'EntryReturnAddress='not in text and'NativeStartImageCallerReturn='not in text
source=OLD/'source/context_inspect.inc';lines=source.read_text().splitlines();line=next(i+1 for i,s in enumerate(lines)if'if(li->image_size!=t->old_size' in s)
review={'status':'INDEPENDENT_PHYSICAL_ENTRY_PROBE_DECODE_PASS_CONTEXT_REFUSED_BEFORE_HEADER_OR_HASH','decode':meta,'same_as_parent_log':True,'screens':[{'path':str(p),'sha256':sha(p)}for p in images],'source_sha256':sha(source),'refusal_line':line,'refusal_expression':'li->image_size != t->old_size','observed_core':{'count':1,'base':'0x54f69000','loaded_image_size':'0x21000'},'expected_original_core':{'pe_size_of_image':'0x20e60','rounded_4096_size':'0x21000','allocation_tail_bytes':416},'exact_cause':'Observed size 0x21000 differs from expected 0x20e60. Short-circuit || returns before this branch attempts header or text reads. The later Core normalized hash was not reached.','what_is_not_proven':['The live PE header SizeOfImage has not yet been checked by this probe.','The live complete Core text/relocation identity has not yet been checked.','No original Core entry return address or native caller frame has been read.','No browser inactivity or installation safety evidence was obtained.'],'bds_original_text_identity_passed':True,'proposed_precise_revision':'For DXE Core only, allow LoadedImage size equal to the exact original PE size or precisely its 4096-byte rounding; require the live PE header, entry, normalized full text and original read bounds to remain the exact original values. Pin the accepted metadata size through allocation callbacks and never read the allocation tail.','old_manifest_sha256':mh,'old_manifest_unchanged':sha(manifest)==mh,'source_script_sha256':sha(Path(__file__)),'remote_or_device_actions':False}
(HERE/'entry_hardware_readonly_review.json').write_text(json.dumps(review,indent=2)+'\n');print(json.dumps({'review_sha256':sha(HERE/'entry_hardware_readonly_review.json'),'status':review['status'],'bytes':len(data),'crc32':meta['crc32']}))
