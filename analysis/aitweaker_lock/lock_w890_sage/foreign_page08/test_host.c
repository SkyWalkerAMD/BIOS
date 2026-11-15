/* TESTONLY host fixtures. Never link this file into a firmware component. */
#include "foreign_page.h"
typedef struct {uintptr_t start;UN bytes;uint32_t access,reserved;} TEST_RANGE;
static NO_IDENTITY identity;static HII database;
static TEST_RANGE ranges[64];static uint32_t range_count,mode,exports,nested;
static uint64_t visit,generation;static HANDLE expected_handle;
static const uint8_t*source;static UN source_bytes;static uintptr_t change_target;static UN change_value;static uint32_t change_bytes;
static uintptr_t nested_page;static FP08_VIEW nested_out;
static void cp(void*d,const void*s,UN n){uint8_t*a=d;const uint8_t*b=s;while(n--)*a++=*b++;}
int EA no_range(uintptr_t p,UN n,uint32_t access){
 if(!n||n>UINTPTR_MAX-p)return 0;
 if(p>=(uintptr_t)&database&&p+n<=(uintptr_t)&database+sizeof(database))return access==NO_READ;
 if(p>=(uintptr_t)&nested_out&&p+n<=(uintptr_t)&nested_out+sizeof(nested_out))return 1;
 for(unsigned i=0;i<range_count;i++)if(p>=ranges[i].start&&p-ranges[i].start<ranges[i].bytes&&n<=ranges[i].bytes-(p-ranges[i].start)&&(ranges[i].access&access)==access)return 1;
 return 0;
}
int EA no_identity(NO_IDENTITY*out){cp(out,&identity,sizeof(identity));return !(mode&256);}
int EA no_native_visit_identity(uint64_t*v,uint32_t*r){*v=visit;*r=0;return visit&&!(mode&512);}
int EA no_catalog_generation(uint64_t*out){*out=generation;return !(mode&1024);}
static ES EA export_fixture(HII*db,HANDLE hii,UN*bytes,void*out){
 exports++;if(db!=&database||hii!=expected_handle)return ERR(14);
 if(mode&1)return ERR(7);
 if(mode&2){*bytes=8u*1024u*1024u+1;return 0;}
 if(*bytes<source_bytes){*bytes=source_bytes;return ERR(5);}
 cp(out,source,source_bytes);*bytes=source_bytes;
 if(mode&4)generation++;
 if(mode&8)identity.epoch++;
 if(mode&16)visit++;
 if(mode&32)for(unsigned i=0;i<change_bytes;i++)((uint8_t*)change_target)[i]=(uint8_t)(change_value>>(8*i));
 if(mode&64)nested=(uint32_t)fp08_describe_page(nested_page,0,&nested_out);
 if(mode&128)database.export_list=0;
 return 0;
}
void EA fp08_test_bind(const NO_IDENTITY*id,uint64_t v,uint64_t g,HANDLE hii,const void*bytes,UN n,const TEST_RANGE*r,uint32_t count){
 cp(&identity,id,sizeof(identity));database.export_list=export_fixture;identity.database=&database;
 visit=v;generation=g;expected_handle=hii;source=bytes;source_bytes=n;range_count=count<=64?count:0;
 for(unsigned i=0;i<range_count;i++)ranges[i]=r[i];mode=exports=0;nested=99;change_target=0;change_bytes=0;nested_page=0;
}
void EA fp08_test_mode(uint32_t m,uintptr_t target,UN value,uint32_t bytes,uintptr_t page){mode=m;change_target=target;change_value=value;change_bytes=bytes;nested_page=page;}
uint32_t EA fp08_test_exports(void){return exports;}
uint32_t EA fp08_test_nested(void){return nested;}
size_t EA fp08_test_identity_bytes(void){return sizeof(NO_IDENTITY);}
