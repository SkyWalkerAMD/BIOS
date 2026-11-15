"""Preserve bounded offline SPI descriptor review progress, without I/O tests."""
from pathlib import Path
import datetime, hashlib, json, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REMOTE = HERE.parent
CASE = REMOTE.parents[2]
ROOT = CASE.parents[2]
sys.path.insert(0, str(ROOT/'tools/pydeps'))
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def evidence(p, ranges):
    lines=p.read_text(encoding='utf8').splitlines()
    return {'path':str(p),'sha256':sha(p),'excerpts':[{'first_line':a,'last_line':b,'lines':[{'line':i+1,'text':lines[i]} for i in range(a-1,b)]} for a,b in ranges]}

references=REMOTE/'read_only_backup_design/references'
manifest=json.loads((REMOTE/'read_only_backup_design/evidence_manifest.json').read_text(encoding='utf8'))
for n in ['flashrom-ichspi.c','linux-spi-intel.c']:
    assert sha(references/n)==manifest['reference_snapshots'][n]
cpu=REMOTE/'cpuio2_native/OriginalCpuIo2.efi'
assert sha(cpu)=='4fe8ca3ca86616c659a55f6a9faac1a2c511dde1de7996a7c46dba8559422f24'
pe=pefile.PE(str(cpu));md=Cs(CS_ARCH_X86,CS_MODE_64)
write=list(md.disasm(pe.get_data(0x484,0x531-0x484),0x484))
assert [i.op_str for i in write if i.mnemonic=='call']==['0x30c']
assert not any(i.mnemonic in ['out','in','wrmsr','syscall'] for i in write)
assert pe.get_data(0x4e4,2).hex()=='8803'
assert pe.get_data(0x4f1,3).hex()=='668903'
assert pe.get_data(0x4fe,2).hex()=='8903'
report={
 'status':'PARTIAL_OFFLINE_STATIC_REVIEW_NO_DESCRIPTOR_CANDIDATE_BUILT',
 'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'reviewer':'/root/sage_remote_identity',
 'scope':'Review planned fixed READ-cycle0 capture of FD 0..0xFFF twice. No flash-data operation or controller operation performed.',
 'actual_actions':{'device_or_BMC_access':False,'physical_MMIO_reads':0,'physical_MMIO_writes':0,'SPI_READ_cycles':0,'flash_program_or_erase':0,'firmware_upload_or_update':False,'native_write_emulation_executed':False,'candidate_compiled':False,'candidate_failure_simulation_executed':False,'candidate_OVMF_test_executed':False},
 'stop_reason':'Parent requested preservation of current evidence because the implementing agent was unable to continue due to a service usage limit. No candidate source or binary exists for final review.',
 'confirmed':[
  {'id':'HSFC16','classification':'OBSERVED_PINNED_UPSTREAM_SOURCE','finding':'flashrom explicitly treats the combined HSFSTS_CTL register as separate HSFS/HSFC halves. HSFC is written with a 16-bit MMIO store at +0x06. Its hardware READ path passes cycle0, encodes FDBC=len-1 and sets FGO. The chipset property branch includes CHIPSET_700_SERIES_RAPTOR_POINT. Local CHIPSEC XML independently describes HSFC +0x06 size2.', 'source_lines':{'flashrom-ichspi.c':['35-38','57-76','128-141','1370-1394','1705-1735','2113-2143'],'spibar0.xml':['24-31']},'limit':'This is primary implementation evidence for partial register access, not an acquired Intel register EDS or physical validation of this particular controller.'},
  {'id':'FADDR32','classification':'OBSERVED_PINNED_UPSTREAM_SOURCE','finding':'FADDR is +0x08 DWORD. flashrom writes the new address while preserving bits outside its PCH100+ address mask0x07FFFFFF; Intel-authored Linux uses a DWORD write of the bounded address directly. A candidate still needs an explicit preservation/validation policy, fixed address bounds and readback.', 'source_lines':{'flashrom-ichspi.c':['76','1293-1298'],'linux-spi-intel.c':['575']},'limit':'No candidate address helper or reserved-bit policy has been reviewed.'},
  {'id':'READ-CONTROL','classification':'OBSERVED_PINNED_UPSTREAM_SOURCE','finding':'Cycle0 is READ; FGO is combined bit16 (HSFC bit0), FCYCLE combined bits17..20, and FDBC combined bits24..29 (HSFC bits8..13). A 64-byte transfer requests HSFC0x3F01 only if other control bits are intentionally zero after validated preconditions. No other opcode is needed for the proposed capture.', 'limit':'Do not silently clear pre-existing FSMIE/WET or reserved bits. If a bounded constant is selected, reject unexpected nonzero FSMIE/WET/reserved bits or provide an evidence-based preservation policy. Old FCYCLE/FDBC are command fields to replace; the observed prior HSFC0x0010 itself is not a protection-bit change.'},
  {'id':'HSFS-W1C','classification':'OBSERVED_PINNED_UPSTREAM_SOURCE','finding':'Both pinned Linux and flashrom explicitly clear FDONE/FCERR/AEL by writing ones. flashrom uses 16-bit HSFS readback writes; Linux uses a combined DWORD RMW. Neither inspected local source demonstrates a low-byte W1C write.', 'source_lines':{'flashrom-ichspi.c':['1330-1382','1717-1719'],'linux-spi-intel.c':['577-583']},'limit':'The existing readback implementation is not adopted automatically: 16-bit HSFS reaches WRSDIS/PRR34_LOCKDN/FLOCKDN bits; combined DWORD reaches both status and control. Precise W1C/RW/RW1S semantics and permitted partial-write width remain a gating question for a narrower alternative.'},
  {'id':'CPU-WRITE-STATIC','classification':'OBSERVED_ORIGINAL_ASUS_MACHINE_CODE','finding':'Original CPU_IO2 Mem.Write RVA0x484 calls only parameter validator0x30C. Width0/1/2 loads the corresponding caller byte/word/DWORD and stores it directly to the supplied address at RVAs0x4E4/0x4F1/0x4FE. This is a general memory-writing protocol; it supplies no SPI opcode, value, register or board whitelist.', 'limit':'No synthetic execution of Mem.Write was completed. Prior native_review.json covers 21 Mem.Read cases only and must not be described as write-path validation or proof of the current live interface.'}
 ],
 'not_established':[
  'Low-byte HSFS W1C write support for this exact target. Do not select it based on presumed byte-enable behavior.',
  'Complete safe whitelist and exact state-machine implementation, including timeout, failed status, readback mismatch, no retry after ambiguous FGO, and controller-state/protection snapshots.',
  'Original CPU_IO2 Mem.Write synthetic execution with exact access size/count and output canaries.',
  'New source/EFI hash, compiler output, per-call write trace and failing-case tests.',
  'New OVMF rejection paths and physical descriptor-read result.',
  'Any complete SPI backup, transfer/recovery route or flash-update acceptance.'
 ],
 'implementation_gates_to_resume':[
  'Carry forward INV04 identity/resource/method mapping gates; independently validate the Write method at protocol offset8, since INV04 treated it as unused.',
  'Require live FREG0 bounded exactly0..0xFFF, descriptor-valid, idle before each operation, FRAP host-read bit0 and PR0..4 read permissions; no permission/protection mutation.',
  'Resolve HSFS write-width and bit semantics from primary evidence before writing candidate control code.',
  'Forbid all device writes except exact reviewed FADDR/HSFS/HSFC accesses with Count1 and known Width. Forbid FDATA writes, PCI command changes, FDOC, RDID/SFDP, software sequencer, flash write/erase/status-write cycles.',
  'Require confirmed FDONE with no error and controller idle before reading FDATA; a timeout or uncertain command completion terminates the capture without another command or a hidden fallback.',
  'Two complete4096-byte passes must match before descriptor bytes are called captured; never fill unavailable bytes from the public CAP.',
  'Report controller MMIO write counts separately from flash programming: zero flash WRITE/ERASE is not zero MMIO writes.'
 ],
 'source_evidence':{
  'flashrom':evidence(references/'flashrom-ichspi.c',[(35,76),(109,145),(1293,1298),(1330,1417),(1705,1735),(2113,2143)]),
  'linux':evidence(references/'linux-spi-intel.c',[(24,58),(551,609)]),
  'chipsec_xml':evidence(REMOTE/'spi_inventory_candidate04/source/reference_documents/spibar0.xml',[(8,31)]),
  'source_manifest':{'path':str(REMOTE/'read_only_backup_design/evidence_manifest.json'),'sha256':sha(REMOTE/'read_only_backup_design/evidence_manifest.json')}
 },
 'upstream_reference_urls':[
  'https://github.com/flashrom/flashrom/blob/0bc4b2ddb0f83e3829e8fad840ece804640c37f3/ichspi.c',
  'https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/drivers/spi/spi-intel.c',
  'https://github.com/chipsec/chipsec/blob/3ada8580d0bc5b7335afeed4e72092a043e5c877/chipsec/cfg/8086/SPI/spibar0.xml'
 ],
 'additional_reference_attempt':{'url':'https://raw.githubusercontent.com/chipsec/chipsec/3ada8580d0bc5b7335afeed4e72092a043e5c877/chipsec/hal/spi.py','web_result':'cache miss','sandbox_GET_result':'blocked by socket sandbox','approved_public_GET_result':'HTTP404','file_saved':False,'conclusion':'No source content acquired; this attempt supplies no byte-write evidence. Public source lookup was authorized by parent; no BMC or target-device endpoint was accessed.'},
 'original_CPU_IO2':{'path':str(cpu),'sha256':sha(cpu),'original_read_report':{'path':str(REMOTE/'cpuio2_native/native_review.json'),'sha256':sha(REMOTE/'cpuio2_native/native_review.json')},'write_entry_rva':'0x484','validator_rva':'0x30C','instructions':[{'rva':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in write]},
 'review_script_sha256':sha(Path(__file__))
}
output=HERE/'progress_review.json'
output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
print(json.dumps({'path':str(output),'sha256':sha(output),'status':report['status']},indent=2))
