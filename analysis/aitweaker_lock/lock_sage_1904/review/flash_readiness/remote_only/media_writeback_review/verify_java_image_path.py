"""Bind an offline Java/JNI image writeback review to the official client bytes.

Does not import a target Java class, load the native DLL, open a socket, or start
the client. Ghidra pseudocode is cross-referenced with native function bytes.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0, str(ROOT/'tools/pydeps'))
import pefile
import capstone


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file(path):
    data = path.read_bytes()
    return {'path':str(path.resolve()), 'bytes':len(data), 'sha256':sha(data)}


def main():
    jar = HERE/'JViewer.jar'
    dll = HERE/'javaharddiskwrapper-win64.dll'
    assert sha(jar.read_bytes()) == '32be6d97032587e1490d2f34ee04a98cd89875e7196936fb2fec5e0440bc3b98'
    raw = dll.read_bytes()
    assert sha(raw) == '0fcc9ee5629d653c9621e057df39c69fb3ef04fba85106d667123d172e25a14a'
    with zipfile.ZipFile(jar) as z:
        assert z.read('com/ami/kvm/jviewer/lib/win64/javaharddiskwrapper.dll') == raw
        classes = {n:sha(z.read(n)) for n in z.namelist() if n.endswith('.class') and any(x in n for x in ['IUSBRedirSession','HarddiskRedir','VMActionListener','RedirectionController','SinglePortKVM','StandAloneConnectionDialog','PacketMaster','JViewer.class','VMApp.class'])}
        manifest = z.read('META-INF/MANIFEST.MF').decode()
        assert 'Main-Class: com.ami.kvm.jviewer.JViewer' in manifest
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase
    assert base == 0x180000000
    image_vtable = struct.unpack('<3Q',pe.get_data(0x12378,24))
    physical_vtable = struct.unpack('<3Q',pe.get_data(0x12618,24))
    assert image_vtable == (base+0x17e0,base+0x1830,base+0x1840)
    assert physical_vtable == (base+0x2780,base+0x28c0,base+0x28f0)
    assert b'CHarddiskImgFileReader' in raw and b'CWinNTHarddiskReader' in raw
    directory = HERE.parent/'jviewerhd_decompile'
    ghidra = json.loads((directory/'function_inventory.json').read_text())
    assert ghidra['executable_sha256'].lower() == sha(raw)
    cs = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    imports = {i.address:i.name.decode() for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports if i.name}
    cs.detail = True
    selected = [0x12c0,0x1440,0x15a0,0x17e0,0x1830,0x1840,0x1a60,0x3270,0x3390,0x3470,0x3520,0x3620,0x3700,0x3840,0x38a0]
    function_addresses = sorted(int(f['address'],16)-base for f in ghidra['functions'] if not f['external'])
    rows = []
    for rva in selected:
        # Chained unwind records split functions into fragments. Hash the full
        # span up to the next recovered function entry, including any padding.
        limit = next(a for a in function_addresses if a>rva)
        data = pe.get_data(rva,limit-rva)
        ins = list(cs.disasm(data,base+rva))
        calls = []
        for i in ins:
            if i.mnemonic not in ('call','jmp') or len(i.operands)!=1:
                continue
            op = i.operands[0]
            target = None
            if op.type==capstone.x86.X86_OP_IMM:
                target = hex(op.imm-base)
            elif op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                target = imports.get(i.address+i.size+op.mem.disp)
            if target:
                calls.append({'rva':hex(i.address-base),'target':target,'bytes':i.bytes.hex()})
        pseudo = next(directory.glob(f'{base+rva:x}-*.c'))
        rows.append({'rva':hex(rva),'end_rva':hex(limit),'span':'up to next recovered function entry, including padding','bytes_sha256':sha(data),'pseudocode':file(pseudo),'calls':calls})
    (HERE/'native_image_function_evidence.json').write_text(json.dumps(rows,indent=2)+'\n')
    image_write = next(r for r in rows if r['rva']=='0x3620')
    assert any(c['target']=='WriteFile' for c in image_write['calls'])
    image_open = next(r for r in rows if r['rva']=='0x3270')
    assert sum(c['target']=='CreateFileW' for c in image_open['calls'])==2
    baseline = json.loads((HERE/'blank_test/baseline.json').read_text())
    assert file(Path(baseline['path']))['sha256']==baseline['sha256_before_test']
    result = {
        'status':'STATIC_IMAGE_FILE_WRITE_PATH_CONFIRMED_NO_CLIENT_OR_HARDWARE_TEST',
        'scope':'Official same-version Java client and JNI native library only; no network, BMC settings, firmware read/write, target-class execution or DLL load.',
        'script':file(Path(__file__)),
        'inputs':{'JViewer.jar':file(jar),'native_win64_library':file(dll),'official_image':file(HERE.parent/'official_bmc/W7901157.ima')},
        'java_class_sha256':classes,
        'selection_chain':[
            {'class':'com.ami.vmedia.gui.VMActionListener','method':'actionPerformed','evidence':'BROWSE_HD_ dispatches to IUSBRedirSession.floppyImageSelector and stores DevicePanel.selectedImagePath; IMG/IMA is the hard-disk image picker despite its historical floppy name.'},
            {'class':'com.ami.iusb.IUSBRedirSession','method':'floppyImageSelector','javap_lines':[1256,1278],'evidence':'JFileChooser.getSelectedFile().getAbsolutePath() supplies the local image path.'},
            {'class':'com.ami.vmedia.RedirectionController','method':'run','javap_lines':[404,416],'evidence':'Selected path and physical-device boolean are passed to startDeviceRedirection.'},
            {'class':'com.ami.iusb.IUSBRedirSession','method':'startDeviceRedirection','javap_lines':[1050,1076],'evidence':'Device type 2 with physical=false selects StartharddiskImageRedir and media type byte 0x80 (USB).'},
            {'class':'com.ami.iusb.IUSBRedirSession','method':'StartharddiskImageRedir','javap_lines':[854,929],'evidence':'Requires .img/.ima, constructs HarddiskRedir(false), passes the same selected path to startRedirection.'},
            {'class':'com.ami.iusb.HarddiskRedir','method':'startRedirection','javap_lines':[709,729,848,900],'evidence':'physicalDevice=false enters newHarddiskReader(false), skips physical-drive name conversion, passes UTF-8 image path to JNI openHarddisk.'}
        ],
        'native_image_chain':{
            'constructor':{'jni_rva':'0x12c0','false_branch_ctor_rva':'0x1a60','class':'CHarddiskImgFileReader','vtable_rva':'0x12378','first_methods':[hex(x-base) for x in image_vtable]},
            'distinct_physical_branch':{'ctor_rva':'0x30e0','class':'CWinNTHarddiskReader','vtable_rva':'0x12618','first_methods':[hex(x-base) for x in physical_vtable]},
            'open':['JNI 0x1440 copies Java byte[] with NUL termination','image vtable[0] 0x17e0 calls 0x3700 with object+0x18 context','0x3700 copies the selected image path (at most 256 bytes) and calls 0x3270','0x3270 converts UTF-8 to UTF-16 and opens that path using CreateFileW(access=0xc0000000, share=0, OPEN_EXISTING=3); fallback is read-only access=0x80000000/share=1 on specific OS errors'],
            'mode':'READ_WRITE=0 / READ_ONLY=2 are returned open modes, not a caller write-enable switch. Tests must require actual mode 0; read-only fallback does not satisfy writeback.',
            'capacity':{'function_rva':'0x3470','sector_bytes':512,'evidence':'GetFileSizeEx of that image handle produces rounded-up 512-byte sector count.'},
            'read':['JNI execute 0x15a0 obtains Java direct buffers and calls vtable[2] 0x1840','0x1840 invokes 0x38a0 using the same image context','SCSI READ(10)=0x28 / READ(12)=0xa8 -> 0x3520 -> SetFilePointerEx + ReadFile on context+0x108 handle'],
            'write':['Same 0x38a0 dispatch, SCSI WRITE(10)=0x2a','0x3390 checks image read-only state and current image handle','0x3620 seeks LBA*512 and invokes WriteFile on context+0x108 using request data at packet+0x3d','This is an actual selected-image file write path, not inference from the physical-disk implementation or an import name'],
            'close':['image vtable[1] 0x1830 -> 0x3840 -> CloseHandle on the image handle'],
            'native_evidence':file(HERE/'native_image_function_evidence.json'),
            'legacy_implementation_limits':['Image write helper does not check WriteFile result or exact written-byte count before returning success; reopen/readback and size/hash verification is mandatory.','Native image range test checks sector count against total but does not establish LBA+count is within image; a custom controlled backend must bound the complete range.','For sector 0 of images above 0x3ec0 sectors the legacy handler contains FAT BPB adjustment logic; this is not a byte-transparent general-purpose disk-copy protocol.','The selected-image path must be a pinned regular local file; extension filtering alone does not exclude Windows device paths.']
        },
        'connection_requirements':{
            'direction':'Desktop initiates connection to BMC; host-to-desktop HTTP callback is not part of the native Java virtual-HD design.',
            'discovery_source':'StandAloneConnectionDialog reads /api/settings/media/instance and /api/kvm/token under an authenticated web session. No endpoint was called by this review.',
            'normal_route':{'fields':['secure_channel','hd_port','hd_secure_port','hd_state','num_hd','kvm_num_hd','license'],'behavior':'HarddiskRedir -> PacketMaster.connectVmedia -> Connection.createSocket(BMC hostname, selected HD port, TLS-or-plain mode). Actual enabled port and reachability remain unverified; do not assume 5123 or reuse CD port.'},
            'single_port_route':{'gate':'single_port_enabled','service':'HDMEDIA','behavior':'HarddiskRedir uses SinglePortKVM.setHTTPConnect("HDMEDIA") against the configured web endpoint. It uses web-session cookie in CONNECT/tunnel setup, then JVIEWER HDMEDIA service negotiation, before IUSB auth. Availability on this actual BMC is not proven merely by client code.'},
            'media_auth':{'method':'HarddiskRedir.SendAuth_SessionToken','opcode_hex':'f2','fields':'Web/KVM session token, token-type, media type byte and instance. Accepted response required; invalid/denied/busy/expired response must stop. Existing web login does not imply any arbitrary media token will work.'},
            'credentials_handling':'Do not pass real passwords/tokens as command-line arguments or save raw session/packet logs. Stock JViewer.main has debug argument logging; a future controlled launcher must provide secret inputs without exposing them.'
        },
        'minimal_client_assessment':{
            'official_vm_only_mode':True,
            'official_vm_mode':'JViewer supports -apptype VMApp (and standalone launch VMApp); it can launch only the virtual-media application rather than normal video redirection.',
            'stock_headless_mode_confirmed':False,
            'reason':'VMApp.launchApp constructs VMFrame/VMDialog and status Swing components, and reused HarddiskRedir/PacketMaster call JViewerApp/VMApp GUI-associated singletons. Stock Java -Djava.awt.headless=true is not established as a working minimal client.',
            'controlled_headless_feasibility':'A separate bounded regular-file backend and IUSB protocol client is feasible from the traced protocol, but is a new implementation requiring offline packet/short-I/O/length/auth/state tests before any BMC connection. No client has been implemented or launched by this review.',
            'do_not_use_physical_device_redirection':True,
            'do_not_infer_new_writeback_session_works_from_current_h5':True
        },
        'local_preparation':{'blank_image':file(Path(baseline['path'])),'baseline':file(HERE/'blank_test/baseline.json'),'status':'Local FAT read-only reopen verification passed; no mount or host writeback test.', 'unusable_file':'WRITEBACK01.img is a failed local 4 MiB mkfs attempt and MUST NOT be used; only WRITEBACK02.img is pinned.'},
        'future_test_plan':[
            'Parent coordinates any authorized BMC session. Observe current HD instance/route/token requirements read-only before enabling a media session; do not alter device-count or BMC settings.',
            'Whitelist the exact new WRITEBACK02.img regular-file path, size, label and marker; reject physical-device paths, symlinks/reparse points, UNC paths, other files and all out-of-image block ranges.',
            'Require media authentication acceptance and read/write mode. Expose only this disposable virtual HD; do not connect KVM keyboard/video from a new helper.',
            'UEFI must locate only the filesystem containing exact IDENTIFY.TXT marker, then write at most 4096 bytes to WRBACK.TXT. No flash reads, internal disk writes or NVRAM changes.',
            'Flush/close on host and backend, disconnect, reopen the local image read-only; verify WRBACK.TXT exact nonce/hash, unchanged marker, unchanged total size and filesystem consistency. Do not count SCSI status as proof.',
            'If route/session/writeback validation fails, stop and retain diagnostic logs without secrets; do not modify the BMC to force support.'
        ],
        'not_established':['Current server-side HD availability/reachability','Working headless client','Successful UEFI writeback','Full SPI backup or recovery capability','Any firmware flash readiness'],
        'javap_evidence':[file(p) for p in sorted(HERE.glob('*.javap.txt'))],
        'ghidra_evidence':file(directory/'function_inventory.json'),
    }
    out = HERE.parent/'java_image_writeback_static.json'
    out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
    print(json.dumps({'path':str(out),'sha256':sha(out.read_bytes()),'status':result['status']}))


if __name__=='__main__':
    main()
