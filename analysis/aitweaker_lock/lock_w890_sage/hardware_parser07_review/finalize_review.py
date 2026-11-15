"""Independent parser review conclusions and additive provenance binding."""
from pathlib import Path
import sys, json, hashlib, struct
sys.dont_write_bytecode = True
H=Path(__file__).resolve().parent;B=H.parent;R=B.parents[2];P=B/'hardware_parser07'
sys.path.insert(0,str(R/'tools/pydeps'))
import pefile, capstone, unicorn
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bind(p):return {'path':p.relative_to(R).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
def load(p):return json.loads(p.read_text())
manifest=P/'component_manifest.json';frozen=load(manifest)
assert sha(manifest)=='eb5cbb859d7e49cd69315d7e133f6a58f7e077dd8467db2b9a82a665d7829104'
for x in frozen['files']+frozen['external_bindings']:assert bind(R/x['path'])==x
j=load(H/'replay_review.json')
assert bind(H/'review_parser.py')==j['review_script']
original=load(P/'original_bounds.json');changed=load(P/'changed_bounds.json')
assert original['control_evidence']['bound_pages']==changed['control_evidence']['bound_pages']
assert len(original['control_evidence']['bound_pages'])==391
assert original['control_evidence']['unresolved_placeholders']==changed['control_evidence']['unresolved_placeholders']
unbound=[x for x in original['native_pages']['pages'] if x['module']=='UNBOUND']
assert len(unbound)==5
reported_bounds=load(P/'bounds_tests.json')
for x,y in zip(j['bounds_cases'],reported_bounds['results']):
    assert x['count']==y['count_fixture'] and x['mode']=={'both_comparisons':'both'}.get(y['mode'],y['mode'])
    assert x['indices']==y['indices'] and x['stop']==y['stopped']['kind']
spf=R/j['original_spf']['path'];raw=spf.read_bytes()
u16=lambda p:struct.unpack_from('<H',raw,p)[0]
u32=lambda p:struct.unpack_from('<I',raw,p)[0]
pages=u32(0x2c);count=u32(pages);slot=pages+4+4*count
offset=u32(slot);guids=u32(0x40)+u32(u32(0x40)+4)
declared=u32(0x44);target=guids+20*u16(offset+8)+18
physical=load(B/'hardware_delta07_review/physical_review.json')['spf']
assert count==physical['source_count']==379 and slot==int(physical['one_past_slot_relative'],16)==0x650
assert offset==physical['candidate_low32']==0 and u16(offset+0x12)==physical['header_parent']==0
assert u16(offset+8)==physical['header_guid_index']==528
assert target==int(physical['computed_guid_read_relative_only'],16)==0xf4ce6 and target+2>declared==0xf245c
pepath=B/'navigation/modules/AMITSE.efi';pe=pefile.PE(str(pepath))
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
instructions=[]
for start,size in [(0x40fff,0x60),(0x41118,0x21)]:
    for i in cs.disasm(pe.get_data(start,size),start):
        instructions.append({'rva':hex(i.address),'bytes':i.bytes.hex(),'op':i.mnemonic,'args':i.op_str})
report={
 'status':'INDEPENDENT_REVIEW_COMPLETE_EXPERIMENT_REPRODUCED_NOT_ACCEPTED_PATCH',
 'reviewed_manifest':bind(manifest),'input_bindings_verified':{'files':9,'external':25},
 'independent_execution':bind(H/'replay_review.json'),
 'tool_versions':{'pefile':pefile.__version__,'unicorn':unicorn.__version__,'capstone':capstone.__version__},
 'physical_fixture_assessment':{
    'instances':13,'ifr_forms':391,'d7_instances':5,'d7_forms':176,'earlier_original_instances':8,'earlier_original_forms':215,
    'per_package_scope_and_form_count_independently_parsed':True,
    'guid_length_hash_form_count_multiset_matches_prior_physical_HII06':True,
    'distinct_equal_content_25fd_instances_preserved':True,
    'interpretation':'A composite of two captures with arbitrary stable model handles. Matching bytes do not bind cross-boot instance identity, live ConfigAccess ownership or simultaneous HII database state.'},
 'loop_review':{
    'independently_executed_contracts':12,'counts':[0,1,2,379],
    'original_entry':'41010 JB skips only count<1; count1 enters index1.',
    'original_backedge':'4112C JBE admits index==count.',
    'tail_only':'JB backedge excludes count for count>=2, but the count1 entry still enters invalid index1.',
    'both_comparisons':'JBE entry and JB backedge visit exactly1..count-1; count0/1 do not enter.',
    'only_text_byte_changes_in_simulation':['0x41011','0x4112D'],
    'disk_pe_unchanged':True,
    'limits':'The isolated41DCC formset lookup is modeled as synthetic-last-package to suppress output mutation. These are comparison contracts, not general validation of corrupt counts/offsets.'},
 'factory_boundary_assessment':{
    'original_native_stop_rva':'0x41052','source_count':count,'declared_source_bytes':hex(declared),
    'one_past_slot_and_first_page_relative':hex(slot),'one_past_value_from_original_page0_low32':offset,
    'candidate_parent':u16(offset+0x12),'candidate_guid_index':u16(offset+8),'guid_table_relative':hex(guids),
    'computed_two_byte_read_relative':hex(target),
    'causal_support':'Original branch bytes executed unchanged; native index379 reads the first page descriptor as a one-past offset, then header fields produce source+F4CE6. Raw original SPF bytes and the complete post-Setup physical sample agree with those constants.',
    'model_effect':'The source is separately mapped only through the declared-region page rounding. The attempted F4CE6 read is unmapped in this model. Real surrounding pool layout is not reproduced.',
    'not_resolved':['First invocation source values and mutation timing on hardware.','Actual source allocation extent/adjacent bytes and why stock firmware completes startup.','Whether a deliberate vendor sentinel/layout contract exists beyond the currently bound data.'],
    'conclusion':'The model exposes a real original-instruction out-of-declaration calculation under these inputs. It does not demonstrate a hardware crash, establish exploitability, or justify changing the factory parser for the password feature.'},
 'differential_review':{
    'native_pages':396,'bound_ifr_pages':391,'unbound_native_group_pages':unbound,
    'bound_control_counts':[13827,13830],
    'all_bound_original_ifr_opcode_bytes_and_native_types_equal':True,
    'added_management':changed['control_evidence']['management'],
    'unchanged_null_ifr_placeholders':original['control_evidence']['unresolved_placeholders'],
    'note':'Five unresolved native placeholders in the bound-control evidence are separately retained; they are not permissions and must not be confused with the five UNBOUND grouping pages.',
    'handlers_executed':False,
    'limits':'Count equality with396 observed native pages is supporting consistency, not proof of full parser semantics, page identity, rendering, callbacks, input or boot.'},
 'provenance_observation':{
    'id':'P07-REVIEW-01','classification':'ADDITIVE_BINDING_GAP_RESOLVED_IN_REVIEW',
    'finding':'The reviewed25 external entries do not directly bind the HII06 physical hash evidence used to call the other8 instances exact originals, nor the imported inspect_setup.py string decoder. Original module SHA checks and SPF hardcoded SHA assertions do remain in the source.',
    'resolution':'This independent review directly parses all13 F6 records, matches package hashes and adds the missing current dependency/log bindings. Frozen input files remain unchanged.'},
 'original_instruction_excerpt':instructions,
 'release_limits':['Two branches changed only in Unicorn memory; no accepted production patch or artifact.','UEFI allocation, notifications, strings, ConfigAccess NOT_FOUND and volatile variables are models.','No native password handling or permission granted by package byte equality.','No complete firmware startup, GUI, updater, FlashBack acceptance or recovery test.'],
 'no_hardware_operations':True,'no_frozen_files_modified':True}
(H/'review.json').write_text(json.dumps(report,indent=2)+'\n')
(H/'README.txt').write_text('''Independent review of hardware_parser07 (frozen eb5cbb85…9104).

The independent execution reproduces all12 loop contracts and all3 full parser cases. All13 model packages /391 forms match the earlier physical HII06 GUID+size+SHA+form-count multiset, with5 complete D7 reconstructions and8 exact original package instances. This is still a cross-capture fixture, not a simultaneous database or owner proof.

With the two emulator-only loop comparisons, both runs produce396 native pages. Original bound control bytes/types remain equal; only Security271D management QIDs FFD0/D1/D2 are added as type27, increasing13827 to13830 controls. Null IFR placeholders and unbound grouping pages remain explicitly unresolved.

The original factory bytes really calculate an out-of-declared-source read in the isolated model. The post-Setup physical source fields agree, but neither establishes first-parser state, actual pool ownership/adjacency or a need to alter the vendor parser. No factory or development PE was changed. This is not boot, GUI, password or FlashBack qualification.

The new review binds the earlier physical log and imported string decoder omitted from the direct input list; it does not alter the frozen producer manifest. Exact evidence, independent replay, limits and original instructions are in review.json/replay_review.json.
''',encoding='utf-8')
extra=[manifest,pepath,spf,B/'hardware_delta07_review/component_manifest.json',B/'hardware_delta07_review/physical_review.json',
       B/'hardware_hii06/reconciled01.json',R/j['fixture_inventory']['earlier_physical_log']['path'],
       B/'diagnostic_hii06/component_manifest.json',R/'analysis/aitweaker_lock/inspect_setup.py']
out={'status':'FROZEN_INDEPENDENT_REVIEW_NOT_RELEASE','local_bindings':[bind(p) for p in sorted(H.iterdir()) if p.is_file() and p.name!='component_manifest.json'],
     'external_bindings':[bind(p) for p in extra]}
(H/'component_manifest.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'report':bind(H/'review.json'),'manifest':bind(H/'component_manifest.json')}))
