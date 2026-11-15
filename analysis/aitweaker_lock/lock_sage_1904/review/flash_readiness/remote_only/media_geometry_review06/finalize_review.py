"""Freeze only this review's bounded results; all other artifacts read-only."""
from pathlib import Path
import datetime,hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BASE=HERE.parent
sha=lambda b:hashlib.sha256(b).hexdigest()
def binding(p):
    b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def main():
    replay=json.loads((HERE/'native_cache_attach_replay.json').read_text());assert replay['status']=='PASS' and replay['case_count']==8
    for row in replay['inputs']:assert sha(Path(row['path']).read_bytes())==row['sha256']
    native=json.loads((HERE/'native_geometry_analysis.json').read_text());assert native['kernel_named_function_count']==91
    scan=json.loads((HERE/'official_scan.json').read_text());assert scan['regular_files_scanned']==2509
    for row in scan['files']:
        if row['output']:assert sha((HERE/row['output']).read_bytes())==row['sha256']
    physical_path=BASE/'linux_capacity_candidate01/review/physical01/hardware_review.json'
    physical=json.loads(physical_path.read_text());s=physical['semantic']
    assert s['userspace_rc10_calls']==2 and s['packets'][0]['sense']=='700006000000000A00000000290000000000'
    assert s['packets'][1]['status']==0 and s['packets'][1]['data8']=='0004000000000400'
    wire_path=BASE/'media_writeback_client01/runs/20261103_095724/result.json'
    wire=json.loads(wire_path.read_text());assert len(wire['capacity_sends'])==1
    w=wire['capacity_sends'][0];assert w['sendall_returned'] and w['capacity8_hex']=='00007fff00000200' and w['frame_bytes']==101
    assert all(wire[x]==0 for x in ['backend_read_calls','backend_write_calls','backend_flush_calls'])
    chain_path=BASE/'update_chain_review05/evidence_manifest.json';chain=json.loads(chain_path.read_text())
    assert sha(chain_path.read_bytes())=='70f183d372c6afade794f1c81a4ebe14b5d74d20b3439b4d2d8fc195b54bde46'
    chain_bad=[row['path'] for row in chain['files'] if sha(Path(row['path']).read_bytes())!=row['sha256']]
    assert not chain_bad and len(chain['files'])==201
    inputs=[physical_path,BASE/'linux_capacity_candidate01/review/physical01/current_helper_capacity_replay.json',wire_path,
            BASE/'continuation07/capacity_observer_review.json',BASE/'media_writeback_client01/runs/20261103_093929/result.json',
            BASE/'media_geometry_review03/geometry_review.json',BASE/'media_geometry_review03/nbd_client_replay.json',
            BASE/'media_geometry_review03/kernel_geometry_replay.json',BASE/'media_attach_review02/capacity_replay.json',chain_path]
    report={
      'schema':'media-geometry-review06/v1','status':'BOUNDED_OFFLINE_REVIEW_COMPLETE_EXACT_LIVE_GEOMETRY_ORIGIN_UNRESOLVED',
      'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
      'actions':'Local reads, pinned official-image extraction, static ARM analysis and Unicorn synthetic-memory replay only. No BMC/network connection, device action, service mutation, shell command execution, firmware upload or flash.',
      'frozen_chain05':{'manifest':binding(chain_path),'verified_artifacts':201,'all_hashes_unchanged':True},
      'new_results':{'actual_ARM_cases':8,'status':'PASS','report':binding(HERE/'native_cache_attach_replay.json'),
                     'static_named_kernel_functions_surveyed':91,'official_regular_files_scanned':2509},
      'physical_fact':{
          'source':binding(physical_path),'target':'ASUS Pro WS W790E-SAGE SE1904 / unique046B:FF31 / Linux1-13.2:1.0 sg0',
          'rc10_commands':2,'first':'UNIT ATTENTION06/29/00;8byte data untouched zero; not a successful capacity response',
          'second_successful_payload':'0004000000000400','last_lba':262144,'block_bytes':1024,'capacity_bytes':268436480,
          'implication':'The same mismatch is visible in a successful Linux SCSI response, so it is not explained solely by OEM UEFI BlockIO cached fields.',
          'count_scope':'The helper startup opcode25 count1 is a separate application-control event count, not the number of host USB/SCSI RC10 commands.'},
      'later_frontend_send_fact':{
          'source':binding(wire_path),'utc':w['utc'],'host_state':'OFF throughout, as reported by parent operator',
          'frame_bytes':101,'capacity_hex':'00007fff00000200','fields':w['fields'],'sendall_returned':True,
          'image_backend_reads_writes_flushes':[0,0,0],'image_bytes':wire['final_image_bytes'],
          'image_sha256':wire['final_image_sha256'],'socket_and_image_closed':wire['socket_closed'] and wire['image_closed'],
          'limit':'This is a later off-host session. It proves those public bytes were handed to the connection successfully, not that BMC accepted/applied them, and is not a same-session capture of the earlier LC01 capacity mismatch.'},
      'confirmed_native_findings':[
          {'id':'wire_fields','addresses':['hdserver0x17054','hdserver0x12E68'],
           'finding':'In the pinned backend, RC10 bytes at packet+61(lastLBA BE32) and+65(blockBytes BE32) become state+0x20(total blocks=last+1 modulo32) and+0x18(block size). A101byte response with expected bytes reaches512/32768 in independently repeated original ARM replay. A deliberate observed-value payload is also accepted as1024/262145; no image-identity/expected-geometry check in this local dispatcher.',
           'limit':'Does not prove the running backend binary identity, actual receive bytes or NBD apply acknowledgement.'},
          {'id':'cached_lun','addresses':['kernel0x807385B0','kernel0x80738778','kernel0x80738794','kernel0x8073743C..0x80737484'],
           'finding':'fsg_lun_open samples backing inode bytes and queue logical size and caches total blocks atLUN+0x10,block size at+0x2C. RC10 reads only those cached fields and emits blocks-1. Actual original nbd_ioctl/size_update can change backing state to16MiB/512 while repeatedRC10 still emits the deliberately initialized old0004000000000400; re-open changes it toexpected00007fff00000200.',
           'limit':'Synthetic old geometry was supplied as a fixture. This proves a persistence mechanism, not where live old geometry originated or that the live LUN is stale.'},
          {'id':'async_attach_and_status','addresses':['hdserver0x17DEC','libsafesystem0x13BC','libsafesystem0xEB4','execdaemon0x10DB0'],
           'finding':'hdisk_start writes selectedNBDpath to lun.N/file via a shell command ending ampersand, then immediately bindsUDC. It checks safe_system<0 only. The shipped execdaemon returns raw system() status through a4byteFIFO and library returns it unchanged. Original hdisk_start replay treats positive256 as success; monitor-thread creation failure also still returns a slot. No geometry readback or background-file-write completion check occurs in this function.',
           'limit':'No shell error/race was induced on BMC; the relationship to the observed mismatch remains unproven.'},
          {'id':'ioctl_results','addresses':['libnbdELF0x163C','kernel0x8066C890'],
           'finding':'The pinnedlibnbd forwards512/32768 but ignores all seven ioctl results. Kernel nb d_alloc_config initializes block size1024. The default alone with16MiB yieldslast0x3FFF, with256MiB yields0x3FFFF; neither is observed0x40000.',
           'limit':'No live ioctl failure or fallback was observed.'}
      ],
      'exact_constant_search':{
          'values':['0x40000','0x40001','0x10000000','0x10000400','0x80002'],
          'scope':'91 named nbd_/fsg_ functions in pinned official5.4.124-ami kernel; .text immediate and untyped word search in hdserver/libnbd/libusbgadget/libmediaredir;2509 regular shipped files scanned for relevant path/decimal literals.',
          'result':'No identified capacity assignment creating exact1024/262145. Kernel0x8073862C immediate0x40000 is a file-mode flag test; hdserver0x17338 immediate0x10000000 feeds sigaction flags. Other raw-word/arithmetic matches are not evidence of geometry.',
          'limit':'Bounded constant search cannot rule out computed values, runtime configuration, another active backing object, different running binaries or state corruption.'},
      'readonly_evidence_needed_to_choose_root_cause':[
          'An authorized vendor-supported read-only diagnostic channel to observe active hddisk lun.N/file, exact selected NBDslot, /sys/block/nbdN/size(in512byte sectors), /sys/block/nbdN/queue/logical_block_size, and already-existing geometry/ioctl error logs.',
          'Identity binding of running hdserver/libnbd/kernel to downloaded1.1.57 native bytes. Exact frontend source match is insufficient for backend identity.',
          'Same-session post-receive/apply evidence, or a standard read-only backend status exposing these values. No such supported existing API was established here.'
      ],
      'limits_and_next_boundary':[
          'Do not change capacity replies or weaken the pinned image/geometry/label/marker gates to match unexplained device values.',
          'No supported safe reset/rebind/service restart is proposed or performed by this review.',
          'Success of control authentication, sendall or RC10 does not prove an image data read, writable path, fullSPIbackup, firmware acceptance or recovery.',
          'Exact live generation of0x40000/1024 remains unresolved. Cached-LUN and ignored-error paths are code-supported candidate mechanisms only.'
      ],
      'external_evidence':[binding(p) for p in inputs]
    }
    # Keep spelling of the native name exact in the frozen prose.
    report['confirmed_native_findings'][3]['finding']=report['confirmed_native_findings'][3]['finding'].replace('nb d_alloc_config','nbd_alloc_config')
    (HERE/'geometry_review.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (HERE/'README-review.txt').write_text(
        'MEDIA GEOMETRY REVIEW06 — OFFLINE ONLY\n'
        '结论：实机容量差异已由 Linux 原始 RC10 响应确认；精确来源仍未查实。\n'
        '新增8个原厂ARM隔离回放通过：已打开LUN会缓存旧容量；底层NBD更新不会自动刷新其RC10结果。\n'
        '原hdserver异步写lun/file后绑定UDC；忽略正数非零shell状态，libnbd另忽略ioctl返回值。\n'
        '这些是实际机器码支持的候选机制；旧容量为合成测试前提，不能称已定位实机根因。\n'
        '随后主机关机时的新会话确认发送101B/00007fff00000200，但sendall返回不是BMC应用确认。\n'
        '未连接BMC、未改变服务/设备/镜像/已发布产物；CHAIN05全部201项哈希保持一致。\n',encoding='utf8')
    files=[binding(p) for p in sorted(HERE.rglob('*')) if p.is_file() and p.name!='manifest.json' and '__pycache__' not in p.parts]
    manifest={'schema':'media-geometry-review06-evidence/v1','report_sha256':sha((HERE/'geometry_review.json').read_bytes()),'files':files}
    (HERE/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    for row in files:assert sha(Path(row['path']).read_bytes())==row['sha256']
    print(json.dumps({'status':report['status'],'cases':8,'report':binding(HERE/'geometry_review.json'),'manifest':binding(HERE/'manifest.json'),'artifacts':len(files),'chain201_unchanged':True},indent=2))
if __name__=='__main__':main()
