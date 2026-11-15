"""Additional P2 binary tests, without modifying the released EFI or ZIP.

UEFI services and persistent files remain synthetic. An interrupted-write test
does not model FAT metadata, a storage controller, power-loss atomicity or USB.
"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import sys
import time

OUT=Path(__file__).resolve().parent
P2=OUT.parent/'probe_p2'
sys.path.insert(0,str(P2))
from verify_extended import ExtendedMachine
from verify import (TAGS,get_module,pefile,ERR,LOADED,POST,CONFIG,
                    UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,
                    UC_X86_REG_RSP,UC_X86_REG_RIP)
from unicorn import UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC

EFI_SHA='a16b2e7e0af6aa48cd375a3a3fbd77e58f60a50edd929751fcfe6951d6df64b5'
ZIP_SHA='c06fafc804b6cedc74003459c49d18da53db7618d21edf72391dcfc2ac43ae64'


class ScenarioMachine(ExtendedMachine):
    def __init__(self,tag,initial='normal',faults=None):
        self.faults=faults or {};self.events=[];self.interrupt_at=None;self.interrupted=False
        self.stack_pointer=0xefff08
        super().__init__(tag,initial)

    def hook(self,u,address,size,user):
        name=self.stubs[address];old=self.case
        selected=self.faults.get(name,old)
        a=u.reg_read(UC_X86_REG_RCX)
        # Allow different protocol lookups / file handles to fail independently.
        if name=='LocateProtocol':selected=self.faults.get('LocateProtocol:'+self.guid(a),selected)
        if name=='CloseFile':selected=self.faults.get('CloseFile:'+str(a),selected)
        if name=='HandleProtocol':
            b=u.reg_read(UC_X86_REG_RDX)
            selected=self.faults.get('HandleProtocol:'+self.guid(b),selected)
        self.case=selected
        try:
            if name==self.interrupt_at:
                assert self.created
                if name=='WriteLog':
                    c=u.reg_read(UC_X86_REG_R8)
                    b=u.reg_read(UC_X86_REG_RDX)
                    n=min(47,self.r64(b))
                    self.created_content[self.created[-1]]=bytes(u.mem_read(c,n))
                self.interrupted=True;u.emu_stop();return
            super().hook(u,address,size,user)
            self.events.append((name,selected,u.reg_read(UC_X86_REG_RAX)))
        finally:self.case=old

    def execute(self):
        self.u.reg_write(UC_X86_REG_RSP,self.stack_pointer);self.w64(self.stack_pointer,0x8ff000)
        self.u.reg_write(UC_X86_REG_RCX,0x3333);self.u.reg_write(UC_X86_REG_RDX,self.st)
        self.u.emu_start(self.entry,0x8ff000,count=250000000)
        if self.interrupted:return None
        assert self.u.reg_read(UC_X86_REG_RIP)==0x8ff000,'instruction budget exhausted'
        return self.u.reg_read(UC_X86_REG_RAX)

    def reset_observations(self):
        self.log=b'';self.output='';self.events=[];self.calls=[]

    def relocate(self,app_base=None,modules_base=None,pool_base=None,stack_base=None):
        if app_base is not None:
            p=pefile.PE(str(P2/'USB/EFI/BOOT/BOOTX64.EFI'));p.relocate_image(app_base)
            self.u.mem_unmap(0x100000,0x100000)
            length=(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
            self.u.mem_map(app_base,length);self.u.mem_write(app_base,p.get_memory_mapped_image())
            self.u.mem_protect(app_base,length,UC_PROT_READ)
            for section in p.sections:
                perms=UC_PROT_READ
                if section.Characteristics&0x20000000:perms|=UC_PROT_EXEC
                if section.Characteristics&0x80000000:perms|=UC_PROT_WRITE
                self.u.mem_protect(app_base+section.VirtualAddress,
                    (max(section.Misc_VirtualSize,section.SizeOfRawData)+4095)&~4095,perms)
            self.entry=app_base+p.OPTIONAL_HEADER.AddressOfEntryPoint
            self.symbols={name:value-0x100000+app_base for name,value in self.symbols.items()}
        if modules_base is not None:
            for i,name in enumerate(('AMITSE','Setup')):
                old,old_bytes=self.module_images[name]
                self.u.mem_unmap(old,(len(old_bytes)+4095)&~4095)
                _,_,raw=get_module(self.tag,name);p=pefile.PE(data=raw)
                address=modules_base+i*0x400000;p.relocate_image(address)
                data=p.get_memory_mapped_image().ljust(p.OPTIONAL_HEADER.SizeOfImage,b'\0')
                self.u.mem_map(address,(len(data)+4095)&~4095)
                self.u.mem_write(address,data);self.u.mem_protect(address,(len(data)+4095)&~4095,UC_PROT_READ)
                self.module_images[name]=(address,data)
                self.w64(self.loaded[0x1111+i*0x1111]+0x40,address)
            self.u.mem_protect(0x700000,0x10000,UC_PROT_READ|UC_PROT_WRITE)
            self.w64(self.browser,modules_base+0x1234);self.w64(self.browser+8,modules_base+0x4321)
            for i in range(3):self.w64(self.config+i*8,modules_base+0x400000+0x1100+i*16)
            self.u.mem_protect(0x700000,0x10000,UC_PROT_READ)
        if pool_base is not None:
            self.u.mem_map(pool_base,0x2000000);self.heap=pool_base
        if stack_base is not None:
            self.u.mem_unmap(0xd00000,0x200000)
            self.u.mem_map(stack_base,0x200000);self.stack_pointer=stack_base+0x1fff08


def check_completed(m,expected_status=0,partial=False):
    result=m.execute();assert result==expected_status,(m.tag,m.case,hex(result or 0),hex(expected_status))
    m.invariants()
    if not expected_status:
        assert m.log.startswith(b'AITWEAKER-PROBE-P2\r\n') and m.log.endswith(b'PROBE_COMPLETE\r\n')
        expected=b'PARTIAL' if partial else b'COMPLETE'
        assert b'COLLECTION_STATUS='+expected+b'\r\n' in m.log
        assert 'Saved ' in m.output or m.case=='no_console'
    else:assert 'Saved ' not in m.output
    return result


def record(tag,category,name,start,**extra):
    return {'tag':tag,'category':category,'name':name,'passed':True,
            'seconds':round(time.perf_counter()-start,3),**extra}


def relocation_cases(tag):
    layouts=[
        ('low_app',{'app_base':0x10000}),
        ('preferred_base',{'app_base':0x140000000}),
        ('high_app',{'app_base':0x100001000}),
        ('high_modules',{'modules_base':0x110000000}),
        ('high_pool',{'pool_base':0x200000000}),
        ('high_stack',{'stack_base':0x300000000}),
        ('all_high',{'app_base':0x100001000,'modules_base':0x110000000,
                     'pool_base':0x200000000,'stack_base':0x300000000}),
        ('above_one_TiB',{'app_base':0x10000101000,'modules_base':0x11000000000,
                     'pool_base':0x20000000000,'stack_base':0x30000000000}),
    ]
    results=[]
    for name,layout in layouts:
        start=time.perf_counter();m=ScenarioMachine(tag);m.relocate(**layout);check_completed(m)
        for module in ('AMITSE','Setup'):assert (tag+'/'+module).encode() in m.log
        assert b'RVA=0x00001120' in m.log
        results.append(record(tag,'relocation',name,start,addresses={k:hex(v) for k,v in layout.items()}))
    return results


COMBINED=[
    ('modules_and_protocols_absent','normal',{'LocateHandles':'no_modules','LocateProtocol':'no_protocols'},0,True,
     [b'LoadedImage.enumerate=0x800000000000000E',b'HiiDatabase.locate=0x800000000000000E']),
    ('no_modules_and_disk_full','normal',{'LocateHandles':'no_modules','WriteLog':'media_full'},ERR(7),True,[]),
    ('unknown_code_and_export_growth','unknown_build',{'ExportPackages':'export_growth'},0,True,
     [b'UNKNOWN_BUILD',b'HII export=0x8000000000000009']),
    ('bad_image_and_write_protection','bad_image',{'OpenFile':'create_denied'},ERR(7),True,[]),
    ('bad_ifr_and_marker_read_error','malformed_hii',{'ReadMarker':'marker_read_error'},ERR(7),True,[]),
    ('multiple_hii_and_removed_packages','multi_hii',{'ExportPackages':'export_removed'},0,True,
     [b'HII form-package handles=3',b'HII export=0x800000000000000E']),
    ('list_growth_and_root_close_error','normal',{'ListPackages':'list_growth','CloseFile':'root_close_error'},ERR(7),True,[]),
    ('hii_method_and_loaded_image_missing','hii_null_method',{'HandleProtocol:'+LOADED:'loaded_missing'},0,True,
     [b'HiiDatabase.missing_method',b'Target modules found=1']),
    ('console_failure_and_999_existing','normal',{'Output':'console_error','OpenFile':'existing_last'},0,False,[]),
    ('post_error_and_config_missing','normal',{'LocateProtocol:'+POST:'post_error_nonnull',
     'HandleProtocol:'+CONFIG:'config_missing'},0,True,[b'AMI.PostManager.interface=ABSENT',b'ConfigAccess.locate=0x800000000000000E']),
    ('bad_list_size_and_flush_error','normal',{'ListPackages':'list_return_oversize','FlushLog':'flush_error'},ERR(7),True,[]),
    ('null_allocation_and_missing_marker','normal',{'AllocatePool':'allocate_null','OpenFile':'missing_marker'},ERR(7),True,[]),
    ('bad_path_and_missing_hii_driver','path_zero_length',{'GetHiiDriver':'driver_missing'},0,True,
     [b'NON_FV_IMAGE',b'HII.driver=0x800000000000000E']),
]


def combination_cases(tag):
    results=[]
    for name,initial,faults,status,partial,needles in COMBINED:
        start=time.perf_counter();m=ScenarioMachine(tag,initial,faults);check_completed(m,status,partial)
        for needle in needles:assert needle in m.log,(name,needle)
        exercised={case for _,case,_ in m.events}
        assert set(faults.values())<=exercised,(name,exercised)
        if name=='console_failure_and_999_existing':assert m.created==['\\AITWK-999.TXT']
        results.append(record(tag,'combined_faults',name,start,initial=initial,faults=faults,
                              expected_return_status=hex(status)))
    return results


RETRIES=[
    ('missing_marker',ERR(7),False),('short_write',ERR(7),False),('flush_error',ERR(7),False),
    ('allocate_second_fail',0,True),('log_end_boundary',ERR(9),False),
    ('list_growth',0,True),('write_error',ERR(7),False),('post_error_nonnull',0,True),
]


def retry_cases(tag):
    results=[]
    for fault,status,partial in RETRIES:
        start=time.perf_counter();m=ScenarioMachine(tag,fault);check_completed(m,status,partial)
        old=dict(m.created_content);m.case='normal';m.reset_observations();check_completed(m)
        assert all(m.created_content[path]==content for path,content in old.items())
        assert len(m.created_content)==len(old)+1
        assert m.created[-1]==f'\\AITWK-{len(old):03d}.TXT'
        results.append(record(tag,'retry_same_loaded_image',fault+'_then_normal',start,
                              prior_files_preserved=True,second_collection_complete=True))
    return results


def interruption_cases(tag):
    results=[]
    for point in ('WriteLog','FlushLog'):
        start=time.perf_counter();m=ScenarioMachine(tag);m.interrupt_at=point
        assert m.execute() is None and m.interrupted
        assert 'Saved ' not in m.output
        for address,data in m.module_images.values():assert bytes(m.u.mem_read(address,len(data)))==data
        retained=dict(m.created_content);assert len(retained)==1
        if point=='WriteLog':assert len(next(iter(retained.values())))==47
        else:assert next(iter(retained.values())).endswith(b'PROBE_COMPLETE\r\n')
        # Fresh boot model: volatile allocations disappear; only selected file bytes survive.
        fresh=ScenarioMachine(tag);fresh.created_content=dict(retained);check_completed(fresh)
        assert fresh.created==['\\AITWK-001.TXT']
        assert all(fresh.created_content[path]==data for path,data in retained.items())
        results.append(record(tag,'interrupted_file_model',point,start,
            incomplete_or_unconfirmed_file_preserved=True,new_boot_uses_next_filename=True,
            actual_fat_or_usb_power_loss_simulated=False))
    return results


def main():
    start=time.perf_counter()
    assert hashlib.sha256((P2/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest()==EFI_SHA
    assert hashlib.sha256((P2.parent/'AiTweaker-P2-免刷写诊断.zip').read_bytes()).hexdigest()==ZIP_SHA
    results=[]
    for tag in TAGS:
        for group in (relocation_cases,combination_cases,retry_cases,interruption_cases):
            rows=group(tag);results.extend(rows)
            print(tag,group.__name__,len(rows),'PASS',flush=True)
    counts=Counter(r['category'] for r in results)
    report={'status':'ADDITIONAL_OFFLINE_SCENARIOS_PASS','case_count':len(results),
            'category_counts':dict(counts),'cases':results,'elapsed_seconds':round(time.perf_counter()-start,2),
            'shipped_efi_sha256':EFI_SHA,'original_p2_zip_sha256':ZIP_SHA,
            'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'p2_binary_changed':False,'password_lock_implemented_in_efi':False,
            'limitations':['UEFI protocols and files are synthetic, not OEM firmware implementations.',
                           'Interrupted-file cases do not simulate FAT or physical USB power-loss recovery.',
                           'High addresses test x64 pointer handling, not motherboard physical memory maps.']}
    (OUT/'additional_verification.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print('Additional EFI scenarios PASS:',len(results),flush=True)


if __name__=='__main__':main()
