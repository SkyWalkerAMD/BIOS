"""Record independent core/dependency review; not an adapter readiness grant."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json
HERE=Path(__file__).resolve().parent
D04=HERE.parent
TX=D04/'ram_transaction05'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf8'))
def bound(path):return {'path':str(path),'sha256':sha(path)}

def main():
    build=read(TX/'build/build.json')
    assert build['efi_sha256']=='3a04ddeca96cd62d4cbad9a453735cfb096f98f7e1731579c7ce938eaeb47767'
    assert sha(TX/'build/TransactionCore05.TESTONLY.efi')==build['efi_sha256']
    for name,digest in build['source_sha256'].items():assert sha(TX/'source'/name)==digest
    p13=D04/'provider13/local_candidate_manifest.json'
    p13_manifest=read(p13)
    for item in p13_manifest['artifacts']:
        path=D04/item['path'];assert sha(path)==item['sha256'] and path.stat().st_size==item['bytes']
    edge=read(HERE/'core_edges_result.json')
    assert edge['transaction_efi_sha256']==build['efi_sha256'] and edge['cases']==16
    scope={
      'status':'CORE_REVIEW_COMPLETE_ADAPTER_AND_HARDWARE_CANDIDATE_PENDING',
      'generated_utc':datetime.now(timezone.utc).isoformat(),
      'hardware_ready':False,'adapter_review_complete':False,'firmware_release_ready':False,
      'confirmed_core_normal_path_blockers':[],
      'core':bound(TX/'build/TransactionCore05.TESTONLY.efi'),
      'source':bound(TX/'source/transaction.c'),'header':bound(TX/'source/transaction.h'),
      'plan':bound(TX/'source/transaction_plan.h'),'build':bound(TX/'build/build.json'),
      'independent_replay':bound(HERE/'core_edges_result.json'),
      'review_source':bound(Path(__file__)),
      'frozen_provider_dependency':bound(p13),'provider_manifest_entries_checked':len(p13_manifest['artifacts']),
      'core_observations':[
        {'lines':[16,24,43,62],'finding':'Fixed five-range geometry, original sizes, signed rel32 and all 12 preimages are checked before target stores. Preparation does not install a partial set.'},
        {'lines':[90,104],'finding':'Only TPL_APPLICATION callers can enter the write transaction. All copy/readback/serializer paths run after RaiseTPL(31); Host.validate must remain read-only and make no Boot Services call.'},
        {'lines':[75,88],'finding':'Rollback walks attempted sites in reverse and restores only exact installer bytes. Unknown bytes are not overwritten; unresolved verification remains resident at high TPL.'},
        {'lines':[106,113],'finding':'Removal refuses nonempty UI/save chains. Malformed state magic/reserved also produces TX_BUSY, so BUSY is not proof that the only issue is a legitimate active frame.'},
        {'lines':[40,42,69,74],'finding':'EBS records a terminal latch and revokes valid owned-state phase. RestoreTPL may deliver the callback synchronously; the core detects this before another service call.'},
        {'lines':[26,45],'finding':'Context/plan/host are trusted caller-owned C objects. The core range checks do not prove TX_CONTEXT or callback objects are disjoint from all five plan ranges; the adapter must establish their provenance.'},
      ],
      'required_adapter_properties':[
        'Discover and bind exact original LoadedImage GUID/base/size/normalized text, current 12 preimages, immutable split template/trampolines and provider byte identity.',
        'Independently establish ownership and nonoverlap of app/context/options, code/state, modules, Core/BDS, service objects, memory-map buffer and current stack.',
        'Validate effective writable supervisor identity mappings for every target window before copy; a write protection exception is not a recoverable core status.',
        'Use permitted TPL for allocation, memory-map refresh, attributes, LoadImage, StartImage and HII. The high-TPL validator cannot invoke these services.',
        'Check ending after every firmware callback boundary; TX_HOLD or TX_ENDED must not proceed to console/QR/ResetSystem/free/unload/RestoreTPL.',
        'Keep all published or potentially cached guard/state/provider/load-options/callback data alive even after successful rollback. A resident app must never return through normal cleanup.',
        'Treat missing provider or StartImage/management publication failure as a transaction rollback/retirement path, not as proof no pointers were published.',
        'Verify owned code RO+X and state RW+NX through actual translations and preserve foreign-page semantic permissions; no direct PTE or CR0.WP changes.',
      ],
      'scope_limits':[
        'Sixteen additional actual-PE cases use explicit fixture TPL/validator behavior. They do not establish adapter correctness.',
        'BSP high TPL does not stop APs or SMM; the documented UEFI BSP browser premise remains.',
        'P04 hardware evidence proves two owned allocation permission cycles and target snapshots only, not a native installer or password UI.',
        'No live device action, actual target EFI launch, firmware upload, flash write, or modification of C08/frozen modules was performed by this review.',
      ],
      'pending_final_bindings':['Actual adapter/app source, generated payload dependencies, final EFI/ISO and manifests','Actual adapter failure/EBS/reentry tests','Independent OVMF and final hardware operation scope review'],
    }
    out=HERE/'core_review.json';out.write_text(json.dumps(scope,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':scope['status'],'provider_manifest_entries_checked':len(p13_manifest['artifacts']),'sha256':sha(out)}))
if __name__=='__main__':main()
