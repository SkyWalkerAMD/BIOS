"""Independently decode the physical EP2 screenshots without changing EP2."""
from pathlib import Path
import hashlib,json,re,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];EP2=HERE/'entry_probe02';CAP=CASE/'remote_172_20_2_162/hardware-native13-entry02-1793698042583'
sys.dont_write_bytecode=True;sys.path.insert(0,str(EP2));from decode_probe import decode
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=EP2/'entry_context02_manifest.json';mh=sha(manifest)
for a in json.loads(manifest.read_text())['artifacts']:assert sha(HERE/a['path'])==a['sha256'],a['path']
images=[CAP/f'page-{n:02}.png'for n in range(1,10)];raw,meta=decode(images)
assert len(raw)==6681 and meta['crc32']=='EB17EA84'and meta['sha256']=='8d71d035b5e8d9929aede2edc758c48b30a98c9ae25031d1b237403e536941e6'
assert raw==(CAP/'hardware-log.txt').read_bytes();text=raw.decode('ascii');out=HERE/'entry02_hardware_review';out.mkdir(exist_ok=True);(out/'independently-decoded.log').write_bytes(raw)
def number(label):return int(re.search(r'^'+re.escape(label)+r'=([0-9A-F]{16})\r?$',text,re.M).group(1),16)
core=text.split('CONTEXT_MODULE DxeCore\r\n')[1].split('CONTEXT_MODULE BdsArch')[0];bds=text.split('CONTEXT_MODULE BdsArch\r\n')[1].split('EntryStackMemoryType')[0]
assert'ContextModuleSize=0000000000021000'in core and'ContextPEImageSize=0000000000020E60'in core and'CoreAllocationRoundingUsed=YES'in core
assert'PASS context module normalized complete text SHA256'in core and'PASS context module normalized complete text SHA256'in bds
assert'PASS exact fixed Core StartImage frame'in text and'NativeCallerModule=AMITSE'in text and'PASS exact known native StartImage callsite'in text
rsp=number('RawEntryRSP');rbp=number('NativeCallerSavedRBP');assert rsp==0x54f68af8 and rbp==0x54f68c29 and rbp==rsp+0x131
assert number('EntryReturnAddress')==0x54f69000+0x88af and number('NativeStartImageCallerReturn')==0x60fa5000+0xa8e6
assert number('EntryStackMemoryType')==4 and number('Warnings')==0
review={'status':'INDEPENDENT_EP2_PHYSICAL_IDENTITY_AND_ONE_PARENT_FRAME_PASS_NOT_IDLE_PROOF','decode':meta,'same_as_parent_log':True,'screens':[{'path':str(p),'sha256':sha(p)}for p in images],'observed':{'core_base':'0x54f69000','core_loaded_allocation_size':'0x21000','core_live_pe_size':'0x20e60','core_entry_rva':'0x1c04','core_complete_normalized_text_passed':True,'bds_base':'0x613b4000','bds_complete_text_passed':True,'stack_type':4,'stack_map_attributes':'0xf','raw_entry_rsp':hex(rsp),'entry_return':'0x54f718af','native_parent_module':'AMITSE','native_parent_return_rva':'0xa8e6','native_parent_saved_rbp':hex(rbp),'warnings':0},'derived_next_frame_candidate':{'function_entry_rva':'0x9f78','function_end_exclusive_rva':'0xaada','entry_rsp_from_saved_rbp_plus_5f':hex(rbp+0x5f),'entry_rsp_from_raw_rsp_plus_190':hex(rsp+0x190),'two_derivations_agree':rbp+0x5f==rsp+0x190,'proposed_next_return_slot':hex(rsp+0x190),'proposed_saved_upper_rbp_slot':hex(rsp+0x188),'next_slot_was_read_by_EP2':False,'next_return_address':None},'limits':['Current observation covers the exact original Core entry and one AMITSE parent only.','The derived next frame slot has not been read on hardware.','A matching RBP relation is not proof that no native browser frame exists farther out.','Actual page-table permissions and installer ownership/rollback remain separate work.'],'browser_absence_proven':False,'installer_run':False,'provider_started':False,'previous_ep2_manifest_sha256':mh,'frozen_ep2_artifacts_verified_unchanged':87,'source_script_sha256':sha(Path(__file__)),'remote_or_device_actions':False}
(HERE/'entry02_hardware_readonly_review.json').write_text(json.dumps(review,indent=2)+'\n');print(json.dumps({'review_sha256':sha(HERE/'entry02_hardware_readonly_review.json'),'bytes':len(raw),'crc32':meta['crc32'],'next_return_slot':hex(rsp+0x190)}))
