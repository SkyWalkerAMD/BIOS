"""Freeze the bounded geometry review and its inputs without changing prior work."""
from pathlib import Path
import hashlib,json,struct
from datetime import datetime,timezone
from trace_nbd import HERE,REMOTE,PRIOR,ROOT

SAGE=REMOTE.parents[2]
HW=SAGE/'remote_172_20_2_162'
HD=REMOTE/'media_writeback_client01'

def digest(p):
    b=p.read_bytes();return {'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

def main():
    hardware=HW/'hardware-usbinv01-1793687929667'
    cap=json.loads((hardware/'manifest.json').read_text())
    assert digest(hardware/'hardware-log.txt')['sha256']=='789aca35a5a208e67da6506f63710031e2c181cc7565f136355a28d2bb6e5612'
    matches=[x for x in cap['capture']['handles'] if x.get('USB_VID')=='046B' and x.get('USB_PID')=='FF31']
    assert len(matches)==1
    target=matches[0]
    assert target['MEDIA_BLOCK_BYTES']=='00000400' and int(target['MEDIA_LAST_BLOCK'],16)==0x40000
    live=json.loads((HD/'runs/20261103_063647/result.json').read_text())
    snapshot={'capture_complete':cap['capture']['complete'],'QR_pages':cap['pages'],'QR_bytes':cap['bytes'],'QR_crc32':cap['crc32'],
              'log_sha256':cap['sha256'],'target_USB_only':target,
              'implied_bytes':(0x40000+1)*1024,
              'live_session_summary':{k:live[k] for k in ['started_utc','finished_utc','opcode_counts','backend_read_calls','backend_write_calls','backend_flush_calls','final_image_bytes','final_image_sha256','status']}}
    (HERE/'observed_geometry.json').write_text(json.dumps(snapshot,indent=2),encoding='utf8')
    expected=bytes.fromhex('00007fff00000200')
    byteorder={'expected_READ_CAPACITY_BE_hex':expected.hex(),'BE_last_lba':struct.unpack('>II',expected)[0],
               'BE_block_size':struct.unpack('>II',expected)[1],'wrong_LE_fields':list(struct.unpack('<II',expected)),
               'actual_UEFI_fields_if_serialized_as_SCSI':struct.pack('>II',0x40000,1024).hex(),
               'finding':'A simple BE/LE reversal of the expected payload does not produce observed UEFI geometry.'}
    kernel=(HERE/'kernel_uncompressed.bin').read_bytes()
    # Independently compare recovered kallsyms to exported symbol records.
    cross=[]
    for name,record,expected_addr in [('fsg_lun_open',0xd25cd0,0x807385b0),('fsg_lun_close',0xd25cb8,0x80738518)]:
        actual=struct.unpack_from('<I',kernel,record)[0];assert actual==expected_addr
        cross.append({'name':name,'export_record_offset':hex(record),'export_value':hex(actual),'matches_recovered_kallsyms':True})
    report={
      'status':'BOUNDED_OFFLINE_REVIEW_COMPLETE_ROOT_CAUSE_UNRESOLVED',
      'created_utc':datetime.now(timezone.utc).isoformat(),
      'scope':'Original public BMC/JViewer byte paths and collected SAGE USB metadata only. No BMC access, hardware action, client modification, firmware update or raw USB request.',
      'observed_hardware':[
        'USB 046B:FF31 has USB_IO and BlockIO. The collected metadata marks media present, removable and writable; BlockSize=1024, LastBlock=262144, SFS absent.',
        'The implied BlockIO geometry is 268436480 bytes (256 MiB plus 1024 bytes), not the pinned 16777216-byte image.',
        'The associated HD session completed F1/00/1A/25 once each and F3 eleven times; actual image reads/writes/flushes remained zero, image SHA256 stayed pristine.',
        'These are cached UEFI BlockIO media fields. The inventory made no READ CAPACITY or BlockIO transfer, so the actual SCSI response bytes are unknown.'
      ],
      'confirmed_original_code':[
        {'component':'JViewer native Windows DLL','addresses':['0x180003470','0x1800034e0','0x1800038a0'],
         'finding':'Image size is rounded up in 512-byte sectors. For 16 MiB the native capacity payload is 00007fff00000200. GetFileSizeEx failure fallback is 512/2880 blocks, not observed 1024/262145.',
         'evidence':['../jviewerhd_decompile/180003470-FUN_180003470.c','../jviewerhd_decompile/1800034e0-FUN_1800034e0.c','../media_writeback_client01/review_legacy_data/native_dispatch.json']},
        {'component':'hdserverapp','addresses':['0x17054','0x12e68'],
         'finding':'The fixed physical payload offsets61/65 are decoded BE; lastLBA+1 and blockSize are sent to nbd_init. Both legacy101-byte and canonical69-byte responses reach identical 512/32768 state in prior actual-ARM replay.',
         'evidence':['../media_attach_review02/capacity_replay.json','../media_attach_review02/hdserver_decompile/00012e68-FUN_00012e68.c']},
        {'component':'libnbd.so.13.4.3','addresses':['ELF RVA0x163c / Ghidra0x1163c','ELF RVA0x2aac / Ghidra0x12aac'],
         'finding':'Actual ARM replay sends NBD_SET_BLKSIZE(512), NBD_SET_SIZE_BLOCKS(32768), then CLEAR_SOCK/BLKROSET/TIMEOUT/SET_SOCK/DO_IT. Every ioctl return is ignored. Thread entry relocations prove nbd_init starts server then client and joins the server thread only, so success is not an acknowledgement of each geometry ioctl.',
         'evidence':['nbd_client_replay.json','nbd_static.json','../media_attach_review02/nbd_decompile/00012aac-nbd_init.c']},
        {'component':'Original ASUS public Linux5.4.124-ami kernel','addresses':['0x8066c890','0x8066d2a8','0x80669b08'],
         'finding':'nbd_alloc_config defaults blockSize to1024. NBD_SET_BLKSIZE accepts512 and replaces it; NBD_SET_SIZE_BLOCKS multiplies count by current blockSize. nbd_size_update sets queue logical/physical blockSize and gendisk capacity in512-byte sectors. Actual bytes with synthetic objects yield512/16777216 bytes for normal input.',
         'evidence':['fit_kernel.json','kernel_function_ranges.json','kernel_disassembly/nbd_alloc_config.txt','kernel_disassembly/nbd_ioctl.txt','kernel_geometry_replay.json']},
        {'component':'Original kernel USB mass-storage gadget','addresses':['0x807385b0','0x8073743c..0x80737484'],
         'finding':'fsg_lun_open reads backing inode size and block queue logical size, computes total blocks by shifting. READ CAPACITY writes totalBlocks-1 and blockSize in BE. There is no observed fixed0x40000 capacity default in these reviewed geometry paths. With16MiB/512 it emits00007fff00000200.',
         'evidence':['kernel_disassembly/fsg_lun_open.txt','kernel_disassembly/fsg_main_thread.txt','kernel_geometry_replay.json']}
      ],
      'limited_inferences':[
        'The normal inspected native/client/backend/NBD/gadget path preserves the intended geometry; ordinary byte-order reversal and512-versus1024 unit mismatch alone do not explain all observed fields.',
        'Ignored userspace errors mean a live authenticated session does not prove NBD geometry configuration succeeded. An actual failure has not been observed.',
        'The default1024 is a plausible clue, not a proven cause: keeping16MiB with1024 givesLastBlock0x3fff;256MiB with1024 gives0x3ffff, neither equals0x40000.',
        'A different active backing object, stale/cached geometry, an OEM UEFI fallback or different running BMC bytes remain possible. No one is selected as root cause.'
      ],
      'unknowns':[
        'Running BMC hdserver/libnbd/kernel bytes have not been read back and matched to the downloaded public1.1.57 image.',
        'Actual ioctl results, active NBD slot, NBD sysfs size/logical_block_size and gadget LUN backing file are unobserved.',
        'Actual USB READ CAPACITY data and OEM UEFI mass-storage fallback/cache behavior remain unobserved in this review.',
        'Kernel replay uses synthetic objects and trapped services, not a kernel boot, scheduler, USB controller, device or actual mounted filesystem.'
      ],
      'next_minimal_steps':[
        'First inspect the original local ASUS1904 USB mass-storage driver for exact fallback values and LastBlock construction, without a new hardware test.',
        'If static OEM code leaves ambiguity, a separate reviewed read-only observation should compare raw READ CAPACITY(10) bytes with current BlockIO fields on only046B:FF31 and the already observed USB path. No reset, write, capacity spoof or selection relaxation.',
        'If an authorized read-only BMC diagnostics channel already exposes NBD sysfs/configfs, compare logical_block_size, size(in512-byte sectors), active gadget LUN file and backing slot. Do not obtain this by changing BMC configuration.'
      ],
      'do_not_change':['WB exact geometry/label/marker gates','pinned16MiB image range','production HD client framing or capacity to match unexplained values','frozen prior artifacts'],
      'byteorder_comparison':byteorder,
      'kernel_symbol_validation':{'count':37840,'relative_base':'0x80008000','full_names_count_and_markers_validated':True,'export_crosschecks':cross},
      'new_replay_counts':{'libnbd_actual_ARM':6,'kernel_actual_ARM_synthetic_objects':7},
      'artifacts':{'hardware_summary':'observed_geometry.json','libnbd_replay':'nbd_client_replay.json','kernel_replay':'kernel_geometry_replay.json'}
    }
    (HERE/'geometry_review.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    inputs=[hardware/'manifest.json',hardware/'hardware-log.txt',HD/'runs/20261103_063647/result.json',
            HD/'review_legacy_data/bounded_legacy.py',HD/'review_legacy_data/native_dispatch.json',HD/'live_writeback03.py',
            PRIOR/'capacity_replay.json',PRIOR/'backend/usr/local/bin/hdserverapp',PRIOR/'backend/usr/local/lib/libnbd.so.13.4.3',
            PRIOR/'nbd_decompile/00012aac-nbd_init.c',PRIOR/'nbd_decompile/function_inventory.json',
            REMOTE/'media_writeback_review/javaharddiskwrapper-win64.dll',REMOTE/'official_bmc/W7901157.ima',
            REMOTE/'jviewerhd_decompile/180003470-FUN_180003470.c',REMOTE/'jviewerhd_decompile/1800034e0-FUN_1800034e0.c',
            ROOT/'tools/zig-x86_64-windows-0.14.1/lib/libc/include/any-linux-any/linux/nbd.h',
            ROOT/'tools/zig-x86_64-windows-0.14.1/lib/libc/include/any-linux-any/linux/fs.h']
    files=[p for p in HERE.rglob('*') if p.is_file() and p.name!='manifest.json']
    manifest={'status':report['status'],'scope':report['scope'],'files':[digest(p) for p in sorted(files)],'read_only_inputs':[digest(p) for p in inputs]}
    (HERE/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    print(json.dumps({'report':digest(HERE/'geometry_review.json'),'manifest':digest(HERE/'manifest.json'),'artifacts':len(files),'inputs':len(inputs)}))
if __name__=='__main__':main()
