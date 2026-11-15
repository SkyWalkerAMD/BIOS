"""Execute only original filename parser in Unicorn, with explicit RAM file/API models.

This is not Windows utility execution, a FlashBack controller model, CAP signature
verification, or a hardware update. All target writes are confined to emulator RAM.
"""
from pathlib import Path
import hashlib,json,struct,sys,time
D=Path(__file__).resolve().parent
ROOT=D.parents[3]
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/vm-pydeps')]
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_ESP,UC_X86_REG_EIP
def sha(b):return hashlib.sha256(b).hexdigest()
def u32(b):return struct.unpack('<I',b)[0]
def p32(x):return struct.pack('<I',x)
CAP=ROOT/'analysis/workstation_20261008/W890_SAGE_0603/Pro-WS-W890E-SAGE-SE-ASUS-0603.CAP'
EXE=D/'sources/BIOSRenamer.exe'
original=CAP.read_bytes();exe=EXE.read_bytes();p=pefile.PE(data=exe)
assert sha(original)=='c7b12934cd0904a9cd4cfca53f656931bd5164e3bc30b99b043c2c2cb39a92d1'
assert sha(exe)=='412449d304c606dc57aa902fdf9bd040b756732b34307d2c274ebe9e06bf8732'
BASE=p.OPTIONAL_HEADER.ImageBase
GUID=bytes.fromhex('194fc14c26c6b64a9deaca6c01fd10cd')
guid_positions=[];start=0
while True:
    at=original.find(GUID,start)
    if at<0:break
    guid_positions.append(at);start=at+1
aligned=[x for x in guid_positions if not x%8]
assert aligned
guid=aligned[0];boot=original.find(b'$BOOTEFI',guid)
assert boot>=0 and boot+0x9e<=len(original)
expected=original[boot+0x91:boot+0x9d].split(b'\0')[0]
assert expected==b'A5709.CAP'

def run(label,input_bytes):
    t=time.monotonic();u=Uc(UC_ARCH_X86,UC_MODE_32)
    image=p.get_memory_mapped_image();u.mem_map(BASE,(len(image)+0xfff)&~0xfff);u.mem_write(BASE,image)
    STACK=0x100000;STOP=0x200000;API=0x300000;DATA=0x500000;HEAP=0x10000000
    u.mem_map(STACK,0x20000);u.mem_map(STOP,0x1000);u.mem_map(API,0x1000);u.mem_map(DATA,0x1000)
    u.mem_map(HEAP,(len(input_bytes)+0x3fff)&~0xfff)
    name_addr=DATA;out_ptr=DATA+0x200;out_size=DATA+0x204
    u.mem_write(name_addr,b'Pro-WS-W890E-SAGE-SE-ASUS-0603.CAP\0')
    sp=STACK+0x18000;u.mem_write(sp,p32(STOP)+p32(out_size));u.reg_write(UC_X86_REG_ESP,sp)
    u.reg_write(UC_X86_REG_ECX,name_addr);u.reg_write(UC_X86_REG_EDX,out_ptr)
    imports={};events=[];allocations=[]
    for d in p.DIRECTORY_ENTRY_IMPORT:
        for imp in d.imports:
            if imp.name and imp.name.decode() in ['CreateFileA','GetFileSize','ReadFile','CloseHandle']:
                addr=API+len(imports)*16;imports[addr]=imp.name.decode();u.mem_write(imp.address,p32(addr))
    def args(n):
        esp=u.reg_read(UC_X86_REG_ESP)
        return [u32(u.mem_read(esp+4+4*i,4)) for i in range(n)]
    def ret(value,cleanup=0):
        esp=u.reg_read(UC_X86_REG_ESP);target=u32(u.mem_read(esp,4));u.reg_write(UC_X86_REG_EAX,value)
        u.reg_write(UC_X86_REG_ESP,esp+4+cleanup);u.reg_write(UC_X86_REG_EIP,target)
    def dispatch(uc,addr,size,userdata):
        name=imports[addr]
        if name=='CreateFileA':
            a=args(7);assert a[1:]==[0x80000000,0,0,3,0x80,0];events.append({'api':name,'access':'GENERIC_READ','creation':'OPEN_EXISTING'});ret(0x41,28)
        elif name=='GetFileSize':
            assert args(2)==[0x41,0];events.append({'api':name,'bytes':len(input_bytes)});ret(len(input_bytes),8)
        elif name=='ReadFile':
            a=args(5);assert a[0]==0x41 and a[1]==HEAP and a[2]==len(input_bytes) and a[4]==0
            u.mem_write(a[1],input_bytes);u.mem_write(a[3],p32(len(input_bytes)));events.append({'api':name,'bytes':len(input_bytes)});ret(1,20)
        elif name=='CloseHandle':
            assert args(1)==[0x41];events.append({'api':name});ret(1,4)
        else:raise AssertionError(name)
    def malloc(uc,addr,size,userdata):
        n=args(1)[0];where=HEAP if not allocations else HEAP+len(input_bytes)+0x1000
        assert n==(len(input_bytes)+10 if not allocations else 13)
        allocations.append({'bytes':n,'address':hex(where)});ret(where)
    def error_print(uc,addr,size,userdata):raise AssertionError('Unexpected parser error path')
    u.hook_add(UC_HOOK_CODE,dispatch,begin=API,end=API+0xfff)
    u.hook_add(UC_HOOK_CODE,malloc,begin=0x406b73,end=0x406b73)
    u.hook_add(UC_HOOK_CODE,error_print,begin=0x401010,end=0x401010)
    u.emu_start(0x401050,STOP,timeout=60_000_000,count=200_000_000)
    assert u.reg_read(UC_X86_REG_EIP)==STOP,'original parser did not return'
    result=u.reg_read(UC_X86_REG_EAX);expected_pointer=HEAP+boot+0x91
    assert result==expected_pointer,(hex(result),hex(expected_pointer))
    output=bytes(u.mem_read(result,13)).split(b'\0')[0]
    assert output==expected
    assert u32(u.mem_read(out_ptr,4))==HEAP and u32(u.mem_read(out_size,4))==len(input_bytes)
    # Original writes a NUL at name+12 in its heap copy. That byte is 0xB2 in
    # this original image, after the earlier natural filename NUL terminator.
    # Compare the entire heap against exactly this one permitted native store.
    expected_heap=bytearray(input_bytes);expected_heap[boot+0x9d]=0
    assert bytes(u.mem_read(HEAP,len(input_bytes)))==bytes(expected_heap)
    assert bytes(u.mem_read(BASE+0x1050,0x1d3))==p.get_data(0x1050,0x1d3)
    return {'name':label,'pass':True,'returned_name':output.decode(),'returned_pointer_relative_to_CAP':hex(result-HEAP),'events':events,'allocations':allocations,'payload_heap_matches_exact_original_store':True,'ram_store':{'CAP_relative_offset':hex(boot+0x9d),'before':input_bytes[boot+0x9d],'after':0,'instruction':'0x4011BC'},'native_parser_bytes_unchanged':True,'seconds':round(time.monotonic()-t,3)}

tests=[run('original_CAP_filename_parser',original)]
# This solely demonstrates that the renaming routine is not an image verifier.
# The altered byte is never written to disk, signed, packaged, uploaded or flashed.
ram=bytearray(original);ram[0x1842000]^=1
tests.append(run('RAM_only_DXE_byte_change_still_names_file_not_controller_acceptance',bytes(ram)))
assert CAP.read_bytes()==original and EXE.read_bytes()==exe
out={'schema':'w890-original-renamer-machinecode-v1','scope':'Original x86 parser 0x401050..0x401222 only; Win32 file APIs and allocation explicitly modeled in emulator RAM; actual original scan and return instructions executed. No FlashBack controller, signature check, update or hardware behavior is modeled.','original_cap_sha256':sha(original),'renamer_sha256':sha(exe),'parser_sha256':sha(p.get_data(0x1050,0x1d3)),'guid_pattern':GUID.hex(),'guid_all_offsets':[hex(x) for x in guid_positions],'first_eight_byte_aligned_guid_offset':hex(guid),'bootefi_offset':hex(boot),'filename_offset':hex(boot+0x91),'filename':expected.decode(),'tests':tests,'passed':len(tests),'original_files_unchanged':True,'source_sha256':sha(Path(__file__).read_bytes())}
(D/'renamer_machinecode_tests.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
print(json.dumps({'passed':len(tests),'filename':expected.decode(),'guid':hex(guid),'bootefi':hex(boot),'tests':[(x['name'],x['seconds']) for x in tests]}))
