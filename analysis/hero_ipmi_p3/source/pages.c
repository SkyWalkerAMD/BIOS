#include "native.h"
#include "tse_audit.h"
#include "ipmi_pages.h"
static GUID db_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID str_guid={0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID access_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static HDB *db;static HSTR *str;static HANDLE owner,hii;static int has_dp,has_access;
static ES EA extract(ACCESS *a,const C16 *r,C16 **p,C16 **out){(void)a;if(!p||!out)return ERR(2);*p=(C16 *)r;*out=0;return ERR(14);}
static ES EA route(ACCESS *a,const C16 *r,C16 **p){(void)a;if(!r||!p)return ERR(2);*p=(C16 *)r;return ERR(14);}
static ES EA callback(ACCESS *a,UN action,uint16_t q,uint8_t t,void *v,UN *r){
 (void)a;(void)q;(void)t;(void)v;if(!r)return ERR(2);*r=0;return action==3||action==4||action==5?0:ERR(3);
}
static ACCESS access={extract,route,callback};
ES pages_publish(void){
 if(!hii)return 0;
 for(unsigned i=0;i<V_COUNT;i++){
  C16 w[160];unsigned j=0;while(j<159&&values[i][j]){w[j]=(uint8_t)values[i][j];j++;}w[j]=0;
  ES e=str->set_string(str,hii,ipmi_value_ids[i],"en-US",w,0);if(FAILED(e))return e;
 }return 0;
}
ES pages_audit(void){if(!hii)return ERR(6);return tse_snapshot("IPMI_PACKAGE",hii,ipmi_forms,sizeof(ipmi_forms));}
ES pages_ready(void){ES e=pages_audit();if(FAILED(e))return e;return tse_last_new_pages==5&&tse_last_cache_match==1?0:ERR(6);}
ES pages_remove(void){
 ES e;if(hii){e=db->remove_packages(db,hii);if(FAILED(e))return e;hii=0;}
 if(has_access){e=gST->bs->uninstall_protocol(owner,&access_guid,&access);if(FAILED(e))return e;has_access=0;}
 if(has_dp){e=gST->bs->uninstall_protocol(owner,&dp_guid,(void *)ipmi_path);if(FAILED(e))return e;has_dp=0;}
 return 0;
}
ES pages_register(void){
 if(hii)return pages_audit();if(FAILED(last_refresh)||!same(report.board,"ROG MAXIMUS Z790 HERO")||!same(report.bios,"3107"))return ERR(15);
 ES e=gST->bs->locate_protocol(&db_guid,0,(void **)&db);if(FAILED(e)||!db)return ERR(14);
 e=gST->bs->locate_protocol(&str_guid,0,(void **)&str);if(FAILED(e)||!str)return ERR(14);
 if(FAILED(e=gST->bs->install_protocol(&owner,&dp_guid,0,(void *)ipmi_path)))return e;has_dp=1;
 if(FAILED(e=gST->bs->install_protocol(&owner,&access_guid,0,&access)))goto fail;has_access=1;
 if(FAILED(e=db->new_packages(db,ipmi_packages,owner,&hii)))goto fail;
 e=pages_publish();if(FAILED(e))goto fail;
 logtext("P3_IPMI_NEW_PACKAGE_REGISTERED\r\n");return pages_audit();
fail:
 (void)pages_remove();return e;
}
