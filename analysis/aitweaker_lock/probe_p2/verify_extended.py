"""Fault-inject the actual P2 EFI, with original modules as read-only fixtures.
This is a synthetic UEFI environment, not a boot of a workstation BIOS.
The native parser guard-page campaign is a separate script/process.
"""
from pathlib import Path
import importlib.util
import hashlib
import json
import re
import struct
import time
import verify as base
from verify import *
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC

CASES = [
    'normal','missing_marker','bad_marker','old_marker','marker_read_error',
    'marker_close_error','marker_length_overflow','existing_log','existing_last',
    'all_logs_full','unreadable_log','existing_close_error','existing_null',
    'create_denied','create_null','short_write','write_error','media_full',
    'media_removed','flush_error','file_close_error','root_close_error',
    'open_volume_error','open_volume_null','fs_missing','fs_null_method',
    'marker_null_read','file_null_write',
    'no_protocols','no_modules','malformed_hii','allocation_failure','unknown_build',
    'allocate_second_fail','allocate_null','hii_null','hii_null_method',
    'list_oversized','list_misaligned','list_empty','list_growth','list_error',
    'list_return_oversize','list_return_misaligned',
    'export_oversized','export_too_small','export_growth','export_return_oversize',
    'export_zero','export_removed','export_buffer_small',
    'driver_missing','config_missing','callback_null','callback_outside',
    'post_error_nonnull','locate_count_excess','locate_null','locate_failed_nonnull',
    'loaded_missing','bad_image','path_zero_length','path_over_limit','valid_path_prefix',
    'multi_hii','log_flood','log_end_boundary','no_console','console_error',
    'null_system_table','missing_boot_services','missing_boot_method','reentry'
]
FILE_FAILURES = set(CASES[1:7] + CASES[9:28])
COMPLETE_CASES = {'normal','existing_log','existing_last','valid_path_prefix',
                  'export_buffer_small','multi_hii','no_console','console_error','reentry'}
NO_LOG_OVERFLOW = {'log_flood','log_end_boundary'}
EARLY_ERRORS = {'null_system_table':ERR(2), 'missing_boot_services':ERR(2),
                'missing_boot_method':ERR(3)}


def package(parts):
    content=b''.join(parts)+b'\x04\0\0\xdf'
    return uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le+struct.pack('<I',20+len(content))+content


def tiny_package():
    # Valid formset with one scoped FORM and matching END opcodes.
    formset=b'\x0e\x97'+uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le+b'\0'*5
    ops=formset+b'\x01\x86\x14\x27\0\0'+b'\x29\x02'*2
    return package([struct.pack('<I',(2<<24)|(4+len(ops)))+ops])


class ExtendedMachine(Machine):
    def __init__(self, tag, case, probe_dir=None, marker_version='P2'):
        self.pool_owned=set();self.open_handles=set();self.created_content={}
        self.alloc_calls=0;self.marker_version=marker_version;self.boundary_set=False
        self.hii_handles=[0x5555];self.checking_old=marker_version=='P1'
        self.returned_existing=[]
        if probe_dir is not None:
            base.OUT=Path(probe_dir)
        super().__init__(tag,case)
        self.probe_dir=base.OUT
        self.symbols={}
        preferred=pefile.PE(str(self.probe_dir/'USB/EFI/BOOT/BOOTX64.EFI')).OPTIONAL_HEADER.ImageBase
        for line in (self.probe_dir/'probe.map').read_text().splitlines():
            m=re.match(r'\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})\s+',line)
            if m:self.symbols[m[1]]=int(m[2],16)-preferred+0x100000
        if case=='multi_hii':
            self.hii_handles=[0x5555,0x5556,0x5557]
            # A valid synthetic English string package containing a canary.
            string_header=struct.pack('<II',52,52)+b'\0'*32+struct.pack('<H',0)+b'en-US\0'
            strings=b'\x14'+ 'DO_NOT_LOG_HII_STRING_CANARY'.encode('utf-16-le')+b'\0\0\0'
            string_pkg=struct.pack('<I',(4<<24)|(4+len(string_header)+len(strings)))+string_header+strings
            self.package=package([self.package[20:-4],string_pkg])
        if case=='log_flood':
            self.hii_handles=list(range(0x5555,0x5555+1000));self.package=tiny_package()
        if case=='no_console':self.w64(self.st+0x40,0)
        if case=='missing_boot_services':self.w64(self.st+0x60,0)
        if case=='missing_boot_method':self.w64(self.bs+0x40,0)
        if case=='hii_null_method':self.w64(self.hii+32,0)
        if case=='fs_null_method':self.w64(self.fs+8,0)
        if case=='marker_null_read':self.w64(self.marker+32,0)
        if case=='file_null_write':self.w64(self.file+40,0)
        if case=='callback_null':self.w64(self.config+16,0)
        if case=='callback_outside':self.w64(self.config+16,0xdeadbeef)
        if case in ('bad_image','path_zero_length','path_over_limit','valid_path_prefix'):
            li=self.loaded[0x1111]
            if case=='bad_image':
                ptr=self.alloc(b'ZZ'+b'\0'*254);self.w64(li+0x40,ptr);self.w64(li+0x48,256)
            else:
                old=bytes(self.u.mem_read(self.r64(li+0x20),24))
                data={'path_zero_length':b'\x01\x01\0\0',
                      'path_over_limit':b'\x01\x01\xff\xff',
                      'valid_path_prefix':b'\x01\x01\x04\0'+old}[case]
                self.w64(li+0x20,self.alloc(data))
        # Protect the shipped application's code/read-only sections and service tables.
        pe=pefile.PE(str(self.probe_dir/'USB/EFI/BOOT/BOOTX64.EFI'))
        self.u.mem_protect(0x100000,0x100000,UC_PROT_READ)
        for s in pe.sections:
            perms=UC_PROT_READ
            if s.Characteristics&0x20000000:perms|=UC_PROT_EXEC
            if s.Characteristics&0x80000000:perms|=UC_PROT_WRITE
            self.u.mem_protect(0x100000+s.VirtualAddress,(max(s.Misc_VirtualSize,s.SizeOfRawData)+4095)&~4095,perms)
        self.u.mem_protect(0x700000,0x10000,UC_PROT_READ)
        self.u.mem_protect(0x800000,0x10000,UC_PROT_READ|UC_PROT_EXEC)

    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr);assert name and not name.startswith('FORBIDDEN'),name
        sp=u.reg_read(UC_X86_REG_RSP);assert sp%16==8
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        e=self.r64(sp+40);case=self.case;handled=True;ret=0
        if name=='ListPackages':
            assert a==self.hii and (b&255)==2 and c==0
            count=len(self.hii_handles)*8
            if not e:
                count={'list_oversized':32776,'list_misaligned':7,'list_empty':0}.get(case,count)
                self.w64(d,count);ret=ERR(5)
            elif case in ('list_growth','list_return_oversize'):
                self.w64(d,self.r64(d)+8);ret=ERR(5) if case=='list_growth' else 0
            elif case=='list_return_misaligned':self.w64(d,7)
            elif case=='list_error':ret=ERR(7)
            else:
                assert self.r64(d)>=count
                u.mem_write(e,b''.join(P64(h) for h in self.hii_handles));self.w64(d,count)
        elif name=='ExportPackages':
            assert a==self.hii and b in self.hii_handles
            if not d:
                n={'export_oversized':16*1024*1024+1,'export_too_small':19}.get(case,len(self.package))
                self.w64(c,n);ret=ERR(5) if case=='export_buffer_small' else ERR(9)
            elif case in ('export_growth','export_return_oversize'):
                self.w64(c,self.r64(c)+1);ret=ERR(9) if case=='export_growth' else 0
            elif case=='export_zero':self.w64(c,0)
            elif case=='export_removed':ret=ERR(14)
            else:
                assert self.r64(c)>=len(self.package)
                u.mem_write(d,self.package);self.w64(c,len(self.package))
        elif name=='ReadMarker':
            if case=='marker_read_error':ret=ERR(7)
            elif case=='marker_length_overflow':self.w64(b,0xffffffffffffffff)
            else:
                data=('AITWEAKER-PROBE-'+self.marker_version+'\r\n').encode()
                if case=='old_marker':data=b'AITWEAKER-PROBE-P1\r\n'
                if case=='bad_marker':data=b'WRONG\r\n'
                assert a==self.marker and self.r64(b)>=len(data)
                u.mem_write(c,data);self.w64(b,len(data))
        elif name=='AllocatePool':
            self.alloc_calls+=1
            if case=='allocate_second_fail' and self.alloc_calls==2:ret=ERR(9)
            elif case=='allocate_null':self.w64(c,0)
            else:handled=False
        elif name=='LocateHandles' and case in ('locate_null','locate_count_excess','locate_failed_nonnull'):
            if case=='locate_null':self.w64(d,3);self.w64(e,0)
            elif case=='locate_count_excess':self.w64(d,4097);self.w64(e,self.alloc(bytes(4097*8)))
            else:self.w64(d,3);self.w64(e,0xdeadbeef);ret=ERR(7)
        elif name=='LocateProtocol' and self.guid(a)==HII and case=='hii_null':self.w64(c,0)
        elif name=='LocateProtocol' and self.guid(a)==POST and case=='post_error_nonnull':
            self.w64(c,0xdeadbeef);ret=ERR(14)
        elif name=='HandleProtocol' and ((self.guid(b)==CONFIG and case=='config_missing') or
                (self.guid(b)==FS and case=='fs_missing') or
                (self.guid(b)==LOADED and a==0x1111 and case=='loaded_missing')):ret=ERR(14)
        elif name=='GetHiiDriver' and case=='driver_missing':ret=ERR(14)
        elif name=='OpenVolume' and case in ('open_volume_error','open_volume_null'):
            if case=='open_volume_error':ret=ERR(7)
            else:self.w64(b,0)
        elif name=='OpenFile' and self.wide(c)!='\\AITWEAKER-PROBE.TAG':
            path=self.wide(c)
            assert a==self.root and e==0 and re.fullmatch(r'\\AITWK-\d{3}\.TXT',path),path
            if d==1:
                if path in self.created_content or case=='all_logs_full' or (case=='existing_last' and path!='\\AITWK-999.TXT') or case=='existing_close_error':
                    self.w64(b,self.existing);self.returned_existing.append(path)
                elif case=='existing_null':self.w64(b,0)
                else:handled=False
            elif case=='create_denied':ret=ERR(8)
            elif case=='create_null':self.w64(b,0)
            else:
                assert path not in self.created_content and path not in self.returned_existing
                handled=False
        elif name=='WriteLog' and case in ('write_error','media_full','media_removed'):
            ret=ERR({'write_error':7,'media_full':11,'media_removed':12}[case]);self.w64(b,0)
        elif name=='CloseFile':
            assert a in self.open_handles,(case,'close without open',hex(a))
            self.open_handles.remove(a)
            if (case,a) in (('marker_close_error',self.marker),('existing_close_error',self.existing),
                           ('file_close_error',self.file),('root_close_error',self.root)):ret=ERR(7)
        else:handled=False
        if handled:self.calls.append(name);u.reg_write(UC_X86_REG_RAX,ret)
        else:super().hook(u,addr,size,user)
        ret=u.reg_read(UC_X86_REG_RAX)
        if name=='Output' and case=='console_error':u.reg_write(UC_X86_REG_RAX,ERR(7))
        if name=='AllocatePool' and not ret and self.r64(c):self.pool_owned.add(self.r64(c))
        if name=='LocateHandles' and not ret and self.r64(e):
            self.pool_owned.add(self.r64(e));self.image_pool=self.r64(e)
        if name=='FreePool':
            assert a in self.pool_owned,(case,'unowned pool free',hex(a))
            self.pool_owned.remove(a)
            if case=='log_end_boundary' and a==getattr(self,'image_pool',None):
                # Controlled internal-state injection: isolate the final append boundary.
                u.mem_write(self.symbols['logbuf'],b'B'*65530)
                self.w64(self.symbols['loglen'],65530);self.boundary_set=True
        if name in ('OpenVolume','OpenFile') and not ret and self.r64(b):
            ptr=self.r64(b);assert ptr not in self.open_handles
            self.open_handles.add(ptr)
        if name=='OpenFile' and d!=1 and not ret and self.r64(b):
            self.created_content[self.wide(c)]=b''
        if name=='WriteLog':
            assert self.created and len(self.open_handles)>=2
            self.created_content[self.created[-1]]=self.log

    def execute(self):
        self.u.reg_write(UC_X86_REG_RSP,0xefff08);self.w64(0xefff08,0x8ff000)
        self.u.reg_write(UC_X86_REG_RCX,0x3333)
        self.u.reg_write(UC_X86_REG_RDX,0 if self.case=='null_system_table' else self.st)
        self.u.emu_start(self.entry,0x8ff000,count=250000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==0x8ff000,'instruction budget exhausted'
        return self.u.reg_read(UC_X86_REG_RAX)

    def invariants(self):
        for address,data in self.module_images.values():assert bytes(self.u.mem_read(address,len(data)))==data
        for address,n in self.allocations.items():
            assert bytes(self.u.mem_read(address-16,16))==b'\xa5'*16
            assert bytes(self.u.mem_read(address+n,16))==b'\xa5'*16
        assert not self.pool_owned,('pool leak',self.pool_owned)
        assert not self.open_handles,('file handle leak',self.open_handles)
        assert b'DO_NOT_LOG_HII_STRING_CANARY' not in self.log

    def run(self):
        start=time.perf_counter();ret=self.execute();case=self.case
        expected=EARLY_ERRORS.get(case,ERR(7) if case in FILE_FAILURES else ERR(9) if case in NO_LOG_OVERFLOW else 0)
        assert ret==expected,(self.tag,case,hex(ret),hex(expected))
        self.invariants()
        if case in NO_LOG_OVERFLOW or case in EARLY_ERRORS:assert not self.log and not self.created
        if case in FILE_FAILURES:assert 'Saved ' not in self.output
        if ret==0:
            assert self.log.startswith(b'AITWEAKER-PROBE-P2\r\n')
            assert self.log.endswith(b'PROBE_COMPLETE\r\n')
            status=b'COMPLETE' if case in COMPLETE_CASES else b'PARTIAL'
            assert b'COLLECTION_STATUS='+status+b'\r\n' in self.log,(case,self.log[-100:])
        if case=='existing_last':assert self.created==['\\AITWK-999.TXT']
        if case=='all_logs_full':assert not self.created and len(self.returned_existing)==1000
        if case=='existing_log':assert self.created==['\\AITWK-001.TXT']
        if case=='log_end_boundary':assert self.boundary_set
        if case=='post_error_nonnull':assert b'AMI.PostManager.interface=ABSENT' in self.log
        if case=='normal':
            for module in ('Setup','AMITSE'):assert (self.tag+'/'+module).encode() in self.log
            assert b'ConfigAccess.Callback' in self.log
        if case=='reentry':
            first=self.log;self.log=b'';self.output=''
            ret=self.execute();assert ret==0;self.invariants()
            assert self.log==first and self.created==['\\AITWK-000.TXT','\\AITWK-001.TXT']
        return {'tag':self.tag,'case':case,'passed':True,'return_status':hex(ret),
                'seconds':round(time.perf_counter()-start,3),'bytes_logged':len(self.log),
                'firmware_images_unchanged':True,'pool_and_file_handles_released':True,
                'allowed_calls_only':True,'heap_canaries_intact':True}


def p1_regressions():
    old=OUT.parent/'probe';saved=base.OUT;findings=[]
    for case in ('log_end_boundary','no_protocols','marker_close_error','post_error_nonnull'):
        m=ExtendedMachine(TAGS[0],case,old,'P1')
        ret=m.execute();m.invariants()
        if case=='log_end_boundary':
            reproduced=ret==0 and len(m.log)==65536 and not m.log.endswith(b'PROBE_COMPLETE\r\n')
        elif case=='no_protocols':reproduced=ret==0 and b'COLLECTION_STATUS=' not in m.log
        elif case=='marker_close_error':reproduced=ret==0 and bool(m.created)
        else:reproduced=b'AMI.PostManager.interface=PRESENT' in m.log
        assert reproduced,case
        findings.append({'case':case,'p1_issue_reproduced':True,'return_status':hex(ret),
                         'bytes_logged':len(m.log)})
    base.OUT=saved
    return findings


def main():
    start=time.perf_counter();old=p1_regressions()
    print('P1 regressions reproduced:',len(old),flush=True)
    results=[]
    for tag in TAGS:
        for i,case in enumerate(CASES):
            m=ExtendedMachine(tag,case);results.append(m.run())
            if case=='normal':(OUT/('MOCK-'+tag+'.txt')).write_bytes(b'SYNTHETIC TEST DATA - NOT A REAL BOARD LOG\r\n'+m.log)
            if i%10==0 or i==len(CASES)-1:print(tag,f'{i+1}/{len(CASES)}',case,'PASS',flush=True)
    report={'status':'OFFLINE_EXTENDED_PASS_NOT_HARDWARE_VALIDATION','p1_regressions':old,
            'cases_per_board':len(CASES),'case_count':len(results),'cases':results,
            'shipped_efi_sha256':hashlib.sha256((OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
            'elapsed_seconds':round(time.perf_counter()-start,2),
            'coverage':['Real shipped x64 EFI instructions and relocation',
              'Six original SHA-checked PE images relocated into read-only non-executable fixture memory',
              'Original IFR packages in synthetic UEFI services; no full motherboard BIOS boot',
              'Every listed scenario is repeated against all three board fixtures',
              'Runtime services, HII mutations and private callbacks must never be invoked',
              'Application code/data page permissions, pool canaries and handle accounting'],
            'limitations':['Not a CPU/chipset/BMC/DRAM or physical UEFI implementation test.',
              'Firmware pointers must reference valid memory as required by the UEFI ABI.',
              'Mock export services do not run OEM HII export-notification callbacks.',
              'No concurrent process creates log files between the existence check and create.',
              'No password lock, physical USB persistence or firmware flashing is validated.']}
    (OUT/'extended_verification.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print('Extended verification passed:',len(results),'cases',flush=True)


if __name__=='__main__':main()
