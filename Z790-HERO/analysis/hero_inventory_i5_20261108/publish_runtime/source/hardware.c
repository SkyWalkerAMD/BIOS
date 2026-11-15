#include "publish_runtime.h"
#include "hero_inventory_plan.h"
#include "hero_hardware_source.h"
#include "hero_hardware_pcie_adapter.h"
typedef struct {
 HPC_PCI_RECORD pci[HPC_PCI_MAX];HHS_PCI_SINK sink;HHS_RESULT result;
 HPC_CAPTURE capture;HPC_CATALOG catalog;HPC_SCRATCH scratch;
 HSC_SOURCE sata_source;HSC_CATALOG sata;
} SNAPSHOT;
static SNAPSHOT initial,recheck;
static uint8_t workspace[270000] __attribute__((aligned(16)));
static int captured;
static int visit(void *user,const HHS_RECORD *record){SNAPSHOT *s=user;int r=HeroHardwarePciVisit(&s->sink,record);return r?r:HeroSataVisit(&s->sata_source,record);}
static ES collect(SNAPSHOT *s){
 memset(s,0,sizeof(*s));size_t needed=HeroHardwareSourceWorkspaceSize();
 if(needed>sizeof(workspace)||HeroHardwareSourceInit(workspace,needed)||HeroHardwarePciSinkInit(&s->sink,s->pci,HPC_PCI_MAX)||HeroSataSourceInit(&s->sata_source))return ERR(4);
 HHS_VISITOR visitor={1,sizeof(visitor),s,visit};ES e=HeroHardwareSourceCollect(gST,workspace,needed,&visitor,&s->result);
 /* First real integration requires complete stable PCI+Block+Disk capture.
  * Any missing optional source stops, never publishes an empty replacement. */
 if(FAILED(e)||!s->result.complete)return FAILED(e)?e:ERR(6);
 if(HeroHardwarePciCapture(&s->sink,&s->result,&s->capture))return ERR(33);
 static const char sys[]="/redfish/v1/Systems/Self",ch[]="/redfish/v1/Chassis/Self";
 HPC_ROUTES routes={sys,ch,sizeof(sys)-1,sizeof(ch)-1};
 int n=HeroPcieCatalogBuild(s->pci,s->sink.used,&routes,&s->capture,&s->catalog,&s->scratch);if(n)return ERR(33);
 n=HeroSataCatalogBuild(&s->sata_source,&s->result,s->pci,s->sink.used,&s->catalog,&routes,&s->sata);return n?ERR(33):0;
}
ES i5_hardware_capture(void){
 if(captured)return ERR(20);ES e=collect(&initial);status("I5_HARDWARE_CAPTURE",e);if(FAILED(e))return e;
 captured=1;status("I5_HARDWARE_PCI",initial.sink.used);status("I5_HARDWARE_DEVICES",initial.catalog.device_count);status("I5_HARDWARE_FUNCTIONS",initial.catalog.function_count);status("I5_HARDWARE_STORAGE",initial.catalog.storage_count);status("I5_HARDWARE_SATA",initial.sata.item_count);return 0;
}
/* Rebuild from current interfaces before every write. Compare the exact
 * emitted identities/relationships, ignoring volatile PCI status-register
 * bytes and enumeration handle ordering that are not inventory properties. */
int i5_hardware_source_valid(void){
 if(!captured||FAILED(collect(&recheck)))return 0;
 const HPC_CATALOG *a=&initial.catalog,*b=&recheck.catalog;
 if(a->item_count!=b->item_count||a->link_count!=b->link_count||a->json_bytes!=b->json_bytes||!eq(a->json,b->json,a->json_bytes))return 0;
 for(unsigned i=0;i<a->item_count;i++)if(a->items[i].kind!=b->items[i].kind||a->items[i].method!=b->items[i].method||!eq(a->items[i].member_uri,b->items[i].member_uri,HPC_URI_MAX)||!eq(a->items[i].collection_uri,b->items[i].collection_uri,HPC_URI_MAX))return 0;
 for(unsigned i=0;i<a->link_count;i++)if(a->links[i].kind!=b->links[i].kind||!eq(a->links[i].parent_uri,b->links[i].parent_uri,HPC_URI_MAX)||!eq(a->links[i].member_uri,b->links[i].member_uri,HPC_URI_MAX))return 0;
 const HSC_CATALOG *x=&initial.sata,*y=&recheck.sata;
 if(x->item_count!=y->item_count||x->link_count!=y->link_count||x->json_bytes!=y->json_bytes||!eq(x->json,y->json,x->json_bytes))return 0;
 for(unsigned i=0;i<x->item_count;i++)if(x->items[i].method!=y->items[i].method||!eq(x->items[i].member_uri,y->items[i].member_uri,HPC_URI_MAX)||!eq(x->items[i].collection_uri,y->items[i].collection_uri,HPC_URI_MAX))return 0;
 for(unsigned i=0;i<x->link_count;i++)if(x->links[i].kind!=y->links[i].kind||!eq(x->links[i].parent_uri,y->links[i].parent_uri,HPC_URI_MAX)||!eq(x->links[i].member_uri,y->links[i].member_uri,HPC_URI_MAX))return 0;
 return 1;
}
ES i5_make_publish_plan(HIP_PLAN_DATA *p){
 if(!captured||!p)return ERR(6);
 int r=HeroInventoryPlanBuild(i5_catalog(),&initial.catalog,&initial.sata,"/redfish/v1/Systems/Self","/redfish/v1/Chassis/Self",p);status("I5_PLAN_RESULT",r);return r?ERR(33):0;
}
