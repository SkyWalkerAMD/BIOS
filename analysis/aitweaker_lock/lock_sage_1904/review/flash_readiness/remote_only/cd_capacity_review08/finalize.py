"""Freeze bounded H5 CD capacity evidence; no target actions."""
from pathlib import Path
import collections, hashlib, importlib.util, json, struct, sys
from datetime import datetime, timezone
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
CASE=BASE.parents[2];HW=CASE/'remote_172_20_2_162'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def info(p):return {'path':str(p.relative_to(ROOT)).replace('\\','/'),'size':p.stat().st_size,'sha256':sha(p)}
def write(p,o):p.write_text(json.dumps(o,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
def main():
    source=BASE/'media_geometry_review06/official_inputs/5308416/usr/local/lib/mod_websocket.so.13.12.6'
    assert sha(source)=='793260a1ade29a6775776dbae84455d51417db1d68a7df9826c616904dba6605'
    inv=json.loads((HERE/'websocket_decompile/function_inventory.json').read_text())
    assert inv['executable_sha256']==sha(source) and inv['selected_function_count']==4
    tests=json.loads((HERE/'native_capacity_replay.json').read_text())
    assert tests['status']=='PASS' and tests['cases']==8 and tests['source_sha256']==sha(source)
    assert tests['test_script_sha256']==sha(HERE/'replay_cd_capacity.py')
    obs=HW/'cd-observer08-1793703687797.jsonl';meta=obs.with_suffix('.jsonl.json')
    records=[json.loads(s) for s in obs.read_text().splitlines()];summary=json.loads(meta.read_text())
    assert len(records)==summary['packets']==34 and not summary['truncated']
    opcodes=collections.Counter(x['opcode'] for x in records if 'opcode' in x)
    assert set(opcodes)=={'f2','f8','f1','25','f3','f7'} and opcodes['25']==2
    sent=next(x for x in records if x.get('opcode')=='25' and x.get('direction')=='sent')
    assert sent['capacity8']=='0000201f00000800' and sent['bytes']==69 and sent['data_length']==8
    spec=importlib.util.spec_from_file_location('elf_evidence',BASE/'update_chain_review05/inspect_chain.py')
    e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e);elf=e.Elf32(source)
    ds=elf.byname['.dynamic'];st=elf.byname['.dynstr'];strings=elf.data[st['offset']:st['offset']+st['size']]
    needed=[strings[n:].split(b'\0',1)[0].decode() for tag,n in struct.iter_unpack('<II',elf.data[ds['offset']:ds['offset']+ds['size']]) if tag==1]
    assert 'libnbd.so.13' in needed
    selected=json.loads((HERE/'native_selected.json').read_text());selected['source_sha256']=sha(source)
    selected['address_convention']='ELF link-time VA; Ghidra analysis adds0x10000, not measured runtime addresses'
    selected['needed_libraries']=needed;write(HERE/'native_selected.json',selected)
    report={
      'status':'BOUNDED_OFFLINE_REVIEW_COMPLETE_LIVE_ROOT_CAUSE_UNRESOLVED',
      'created_utc':datetime.now(timezone.utc).isoformat(),
      'scope':'Public original ASUS BMC1.1.57 H5 WebSocket CD proxy, frozen parent-captured metadata and eight synthetic original-ARM cases. No BMC connection, client start, device/OS manipulation or firmware modification.',
      'source':info(source),'address_convention':selected['address_convention'],
      'captured_observation':{'evidence':[info(obs),info(meta)],'records':34,'opcode_counts':dict(opcodes),
         'socket_path':'/cd-server','authenticated_status':1,'capacity_hex':sent['capacity8'],'iso_bytes':16842752,
         'derived_last_lba':8223,'derived_blocks':8224,'derived_block_size':2048,
         'finding':'Within this completed trace there are no A8 or28 read frames, not merely no28. One F7 sent then socket closed; this is not proof backend teardown succeeded.'},
      'confirmed_original_code':[
        {'component':'WebSocketProxy','rvas':['0x76b4','0x76fc','0x7704'],
         'finding':'After accepted F1 status1/27/28, proxy forwards F1, builds zeroed62-byte opcode25 request and sends it. Initial READ CAPACITY is proxy startup work; it does not establish host-issued SCSI or USB enumeration.'},
        {'component':'WebSocketProxy','rvas':['0x771c','0x7840','0x7898','0x78c4'],
         'finding':'Decoded capacity payload at offsets61 and65 is byte-swapped from BE. The latter becomes64-bit block size, former+1 becomes64-bit block count (high halves explicitly0), readonly halfword1. nbd_init(context+0x34) then pthread_create(WebSCSIHndlr) follow. For observed bytes this is2048×8224=16842752, no local size rejection or fallback observed in this branch.'},
        {'component':'WebSocketProxy','rvas':['0x789c','0x78d8','0x78f8'],
         'finding':'nbd_init return-1 exits proxy thread; worker pthread_create failure disconnects NBD, sendsF7 to CDserver and exits. Successful local return is not a client-visible acknowledgement of each NBD geometry ioctl.'},
        {'component':'WebSCSIHndlr','rvas':['0x6bc0','0x6bc4','0x6d74','0x6bfc','0x6d28'],
         'finding':'Selects nbd_dev_list[chosen NBD slot], calls cdrom_start, then reads NBD requests. The worker constructs opcodeA8 (READ12), not28. Gadget-start or NBD-request error disconnects. READ12 packet construction for one sector is executed in the native replay.'},
        {'component':'cdrom_start','rvas':['0xe340','0xe3ac','0xe434','0xe444','0xe478'],
         'finding':'Finds an unused /tmp/cd0..3 marker; asynchronously assigns selected NBD path to cdrom LUN file (background ampersand), then binds UDC p1. Only negative safe_system return is treated as failure; synthetic nonnegative256 remains accepted. Eject-monitor thread creation failure is logged but chosen slot still returned. These are exact local code limitations, not proof of live command failure.'},
        {'component':'shared dependency','needed':'libnbd.so.13','evidence':'../media_geometry_review03/nbd_client_replay.json',
         'finding':'H5 CD and HD use the same public libnbd implementation. Previous bounded original-ARM evidence showed individual geometry ioctl returns ignored. This permits the same class of backend uncertainty; it does not prove same live NBD instance, cross-device collision, cached CD geometry, or current fault.'}
      ],
      'tests':{'evidence':info(HERE/'native_capacity_replay.json'),'status':'PASS','cases':8,
               'scope':tests['scope'],'not_hardware_tests':True},
      'correction':'Legacy cdserverapp alone has no libnbd imports and is not the complete H5 receive/backend route. Conclusions here use mod_websocket.so instead; the initial legacy-only observation cannot exclude H5 NBD use.',
      'unresolved':[
        'Public same-version native ELF was not read back from the live BMC; exact live backend binary/state is unobserved.',
        'Observer sent records do not establish completed server decode, nbd_init/ioctl success, worker creation, asynchronous LUN open, UDC bind or host USB enumeration.',
        'No actual live CD READ CAPACITY response or kernel cached CD geometry was collected in this trace.',
        'No common live NBD slot, shared CD/HD collision, causal cache issue or unique repair is proven.',
        'WebSocket framing/authentication and whole BMC scheduling are outside the eight branch fixtures; positive wait-status injection is hypothetical.'
      ],
      'actions':'No live operations. Ordinary reviewed F7/Stop/restart outcomes require parent-run readback; this report proposes no shell/sysfs/service or nonstandard recovery command.'
    }
    write(HERE/'cd_capacity_review.json',report)
    owned=[HERE/'BmcSelectedDecompile.java',HERE/'websocket.regex.txt',HERE/'run_decompile.py',HERE/'native_selected.json',HERE/'replay_cd_capacity.py',HERE/'native_capacity_replay.json',HERE/'finalize.py',HERE/'cd_capacity_review.json']
    owned+=sorted((HERE/'disassembly').glob('*.txt'))+sorted((HERE/'websocket_decompile').glob('*.c'))+[HERE/'websocket_decompile/function_inventory.json']
    refs=[source,obs,meta,BASE/'update_chain_review05/inspect_chain.py',BASE/'component_backend_review/build_component_evidence.py',BASE/'run_headless.py',
          BASE/'media_attach_review02/backend/usr/local/lib/libnbd.so.13.4.3',BASE/'media_attach_review02/nbd_decompile/00012aac-nbd_init.c',
          BASE/'media_geometry_review03/nbd_static.json',BASE/'media_geometry_review03/nbd_client_replay.json',
          BASE/'media_geometry_review06/geometry_review.json',BASE/'media_geometry_review06/native_cache_attach_replay.json',
          BASE/'media_disconnect_client05_review/helper05_review.json',BASE/'media_disconnect_client05_review/manifest.json']
    manifest={'status':'FROZEN','review':info(HERE/'cd_capacity_review.json'),'artifacts':[info(p) for p in owned],'external_inputs':[info(p) for p in refs],
              'exclusions':'Ghidra project/cache and full JVM logs omitted; no credentials, raw session tokens or private auth payloads included.'}
    write(HERE/'manifest.json',manifest)
    print(json.dumps({'review':info(HERE/'cd_capacity_review.json'),'manifest':info(HERE/'manifest.json'),'artifacts':len(owned),'external_inputs':len(refs),'tests':8}))
if __name__=='__main__':main()
