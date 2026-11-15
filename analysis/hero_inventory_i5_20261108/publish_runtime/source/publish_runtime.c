#include "publish_runtime.h"
#if defined(I5_RAM_VALIDATION)
#define I5_PUBLISH_MAX_MS 600000u
#else
#define I5_PUBLISH_MAX_MS 120000u
#endif
#define I5_PUBLISH_MAX_REQUESTS 640u
static HIP_PLAN_DATA plan;
static uint8_t context[131072] __attribute__((aligned(16)));
static HANDLE budget_event,deadline_event;static volatile uint32_t timer_ticks;static int attempted,active,expired;
static uint64_t epoch;
ES i5_make_publish_plan(HIP_PLAN_DATA *);
static void EA tick(HANDLE e,void *p){(void)e;(void)p;if(timer_ticks<60001)timer_ticks++;}
uint32_t i5_publish_elapsed_ms(void){return expired?I5_PUBLISH_MAX_MS:timer_ticks*10u;}
int i5_publish_budget_ok(void){
 if(!active||!deadline_event)return 0;if(expired)return 0;
 ES (EA *check)(HANDLE)=(void *)gST->bs->check_event;
 ES e=check?check(deadline_event):ERR(3);
 /* One-shot timer signal is latched. Periodic callbacks can coalesce at
  * elevated TPL; their count is diagnostic, never the sole total deadline. */
 if(e!=ERR(6)||timer_ticks*10u>=I5_PUBLISH_MAX_MS)expired=1;
 return !expired;
}
ES i5_publish_authorize(const HIP_REQUEST *r){
 if(!r||!i5_publish_budget_ok()||i5_current_tpl()!=4||!i5_source_valid())return ERR(15);
 if(r->method&&!i5_hardware_source_valid())return ERR(15);
 if(!i5_publish_budget_ok())return ERR(18);
 int n=HeroInventoryPublishAuthorize(context,r,epoch,1,i5_publish_elapsed_ms());return n?ERR(15):0;
}
ES i5_publish_current_host(void){
 if(attempted||i5_current_tpl()!=4)return ERR(15);attempted=1;
 if(HeroInventoryPublishContextSize()>sizeof(context))return ERR(4);
 ES e=i5_make_publish_plan(&plan);if(FAILED(e))return e;status("I5_PUBLISH_MAX_MS",I5_PUBLISH_MAX_MS);
 status("I5_PLAN_RESOURCES",plan.resource_count);status("I5_PLAN_LINKS",plan.link_count);
 epoch=i3_inventory_source_epoch();if(!epoch)return ERR(15);
 e=gST->bs->create_event(0x80000200,8,tick,0,&budget_event);if(FAILED(e))return e;
 e=gST->bs->create_event(0x80000000,0,0,0,&deadline_event);if(FAILED(e)){gST->bs->close_event(budget_event);budget_event=0;return e;}
 e=gST->bs->set_timer(deadline_event,2,(uint64_t)I5_PUBLISH_MAX_MS*10000u);
 if(!FAILED(e))e=gST->bs->set_timer(budget_event,1,100000);
 if(FAILED(e)){gST->bs->close_event(budget_event);gST->bs->close_event(deadline_event);budget_event=deadline_event=0;return e;}
 active=1;timer_ticks=0;expired=0;
 int r=HeroInventoryPublishInit(context,sizeof(context),&plan,epoch,I5_PUBLISH_MAX_REQUESTS,I5_PUBLISH_MAX_MS);
 while(r==HIP_READY&&i5_publish_budget_ok()){
  HIP_REQUEST request;r=HeroInventoryPublishNext(context,epoch,i5_source_valid(),i5_publish_elapsed_ms(),&request);
  if(r!=HIP_READY)break;
  status("I5_PUBLISH_SEQUENCE",request.sequence);status("I5_PUBLISH_METHOD",request.method);status("I5_PUBLISH_RESOURCE",request.resource_index);
  HIP_RESPONSE response;e=private_tls_publish_exchange(&request,&response);
  if(FAILED(e)){memset(&response,0,sizeof(response));response.sequence=request.sequence;response.transport_result=1;}
  r=HeroInventoryPublishAccept(context,&response);
 }
 if(r==HIP_READY&&!i5_publish_budget_ok())r=HIP_BUDGET;
 status("I5_PUBLISH_RESULT",r);status("I5_PUBLISH_ELAPSED_MS",i5_publish_elapsed_ms());
 HIP_STATE state;if(HeroInventoryPublishState(context,&state)==HIP_READY){status("I5_PUBLISH_REQUESTS",state.requests);status("I5_PUBLISH_WRITES",state.writes);status("I5_PUBLISH_VERIFIED",state.verified);status("I5_PUBLISH_INDEXED",state.indexed);status("I5_PUBLISH_UNKNOWN_WRITE",state.unknown_write);}
 active=0;e=gST->bs->set_timer(budget_event,0,0);ES close=gST->bs->close_event(budget_event);if(!FAILED(close))budget_event=0;
 ES de=gST->bs->set_timer(deadline_event,0,0),dc=gST->bs->close_event(deadline_event);if(!FAILED(dc))deadline_event=0;
 if(FAILED(de)||FAILED(dc))return FAILED(de)?de:dc;
 if(FAILED(e)||FAILED(close))return FAILED(e)?e:close;
 return r==HIP_COMPLETE?0:r==HIP_BUDGET?ERR(18):ERR(7);
}
