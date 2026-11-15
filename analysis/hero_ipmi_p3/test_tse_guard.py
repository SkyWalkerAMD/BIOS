"""Exercise actual compiled UEFI read guard against gaps, MMIO and overflow."""
from pathlib import Path
import ctypes as c,struct,random,subprocess,json
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
subprocess.run([str(ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0',
 '/export:tse_readable','/out:'+str(P/'tse_test.dll'),str(P/'tse_guard.obj'),str(P/'common.obj')],check=True)
lib=c.CDLL(str(P/'tse_test.dll'));fn=lib.tse_readable
fn.argtypes=[c.c_void_p,c.c_size_t,c.c_size_t,c.c_uint64,c.c_uint64];fn.restype=c.c_int
def desc(t,start,pages):return struct.pack('<IIQQQQ',t,0,start,0,pages,0)
def call(b,addr,n,stride=40):return bool(fn(c.create_string_buffer(b),len(b),stride,addr,n))
tests=0
def check(value,expect):
 global tests
 assert value==expect;tests+=1
m=desc(3,0x1000,1)+desc(4,0x2000,1)+desc(11,0x3000,1)+desc(7,0x4000,1)+desc(6,0x5000,1)
for start,n,ok in [(0x1000,8192,1),(0x1fff,2,1),(0x2fff,2,0),(0x3000,1,0),(0x4000,1,0),(0x5000,4096,1),(0x5fff,2,0),(0,1,0),(0x1000,0,0),(0xffffffffffffffff,2,0),(0x1000,0xffffffffffffffff,0)]:check(call(m,start,n),bool(ok))
for b in [b'',m[:-1],desc(4,0x1001,1),desc(4,0xfffffffffffff000,2),desc(4,0x1000,2**64-1)]:check(call(b,0x1000,1),False)
check(call(m,0x1000,1,39),False);check(call(m,0x1000,1,257),False)
for t in range(16):check(call(desc(t,0x1000,1),0x1000,4096),1<=t<=6)
# Random interval comparison uses an independent page-set oracle.
r=random.Random(0x790)
for _ in range(5000):
 kinds=[r.randrange(16) for i in range(16)]
 blob=b''.join(desc(t,(i+1)*4096,1) for i,t in enumerate(kinds))
 start=r.randrange(0,18*4096);n=r.randrange(0,5*4096)
 allowed={i+1 for i,t in enumerate(kinds) if 1<=t<=6}
 ok=bool(start and n) and all(page in allowed for page in range(start//4096,(start+n-1)//4096+1))
 check(call(blob,start,n),ok)
report={'passed':True,'checks':tests,'coverage':['adjacent descriptors','gaps','MMIO rejection','free memory rejection','overflow','descriptor stride','random page oracle']}
(P/'tse-guard-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(report)
