/* Native BIOS form registration. No standalone SendForm, no flash/NVRAM writes.
 * The RAM-loaded driver may remain resident until reset so firmware can display
 * its registered formset after the launcher returns. */
#include "p1.h"
#include "hii_abi.h"
#include "forms.h"
static GUID db_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID string_guid={0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}};
static GUID access_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID service_guid=P1_API_GUID;
static HDB *db;static HSTR *strings;static HANDLE owner,hii;
static unsigned has_dp,has_access,has_api,in_callback;
static ES EA extract(ACCESS *this,const C16 *req,C16 **progress,C16 **results){
 (void)this;if(!progress||!results)return ERR(2);*progress=(C16 *)req;*results=0;return ERR(14);
}
static ES EA route(ACCESS *this,const C16 *req,C16 **progress){
 (void)this;if(!req||!progress)return ERR(2);*progress=(C16 *)req;return ERR(14);
}
static void publish(void){
 for(unsigned i=0;i<V_COUNT;i++){
  C16 w[160];unsigned j=0;while(j<159&&values[i][j]){w[j]=(uint8_t)values[i][j];j++;}w[j]=0;
  ES e=strings->set_string(strings,hii,value_ids[i],"en-US",w,0);
  if(FAILED(e)){logtext("HII_STRING_FAILED ");loghex(value_ids[i],4);logtext(" ");loghex(e,16);logtext("\r\n");}
 }
}
static ES EA refresh(void){ES e=p1_collect();publish();return e;}
static ES EA callback(ACCESS *this,UN action,uint16_t question,uint8_t type,void *value,UN *request){
 (void)this;(void)type;(void)value;if(!request)return ERR(2);*request=0;
 logtext("P1_CALLBACK action=");loghex(action,8);logtext(" question=");loghex(question,4);logtext("\r\n");
 if(action==3||action==4||action==5)return 0;
 if(question==1&&action==0)return 0;
 if(question!=1||action!=1)return ERR(3);
 if(in_callback)return ERR(20);in_callback=1;refresh();in_callback=0;return 0;
}
static ACCESS access={extract,route,callback};
static const char *EA get_log(UN *n){if(n)*n=audit_len;return audit;}
static const char *EA get_value(unsigned i){return i<V_COUNT?values[i]:0;}
static ES EA native_link(void){return ERR(3);} /* Hook added only after exact target IFR validation. */
static P1_API api={1,sizeof(P1_API),refresh,get_log,get_value,native_link};
static ES EA unload(HANDLE image){
 (void)image;if(in_callback)return ERR(15);ES e;
 if(has_api){e=gST->bs->uninstall_protocol(owner,&service_guid,&api);if(FAILED(e))return e;has_api=0;}
 if(hii){e=db->remove_packages(db,hii);if(FAILED(e))return e;hii=0;}
 if(has_access){e=gST->bs->uninstall_protocol(owner,&access_guid,&access);if(FAILED(e))return e;has_access=0;}
 if(has_dp){e=gST->bs->uninstall_protocol(owner,&dp_guid,(void *)vendor_path);if(FAILED(e))return e;has_dp=0;}
 return 0;
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt)return ERR(2);void *old=0;
 ES e=gST->bs->locate_protocol(&service_guid,0,&old);if(e!=ERR(14))return FAILED(e)?e:ERR(20);
 logtext("HERO-IPMI-P1 / Native HII class 0014 / reads only\r\n");
 detect_board();logtext("BOARD ");logtext(report.board);logtext(" BIOS ");logtext(report.bios);logtext("\r\n");
 for(unsigned i=0;i<V_COUNT;i++)value_text(i,"Not queried");
 value_text(V_RESULT,"Use Refresh BMC information to query the card.");
 if(FAILED(e=gST->bs->locate_protocol(&db_guid,0,(void **)&db))||!db)return FAILED(e)?e:ERR(14);
 if(FAILED(e=gST->bs->locate_protocol(&string_guid,0,(void **)&strings))||!strings)return FAILED(e)?e:ERR(14);
 LOADED *loaded=0;if(FAILED(e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded))||!loaded)return FAILED(e)?e:ERR(14);
 loaded->unload=unload;
 if(FAILED(e=gST->bs->install_protocol(&owner,&dp_guid,0,(void *)vendor_path)))goto fail;has_dp=1;
 if(FAILED(e=gST->bs->install_protocol(&owner,&access_guid,0,&access)))goto fail;has_access=1;
 if(FAILED(e=db->new_packages(db,hii_packages,owner,&hii)))goto fail;
 if(FAILED(e=gST->bs->install_protocol(&owner,&service_guid,0,&api)))goto fail;has_api=1;
 publish();logtext("P1_HII_REGISTERED\r\n");return 0;
fail:
 if(FAILED(unload(image)))return 0;return e;
}
