/* P1b: reuse the HERO native browser and existing Setup formset in RAM.
 * No standalone form browser, external ConfigAccess callback, or NVRAM write. */
#include "native.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID service_guid=P1_API_GUID;
static HANDLE owner;
static ES EA refresh(void){ES e=p1_collect();ES p=native_publish();return FAILED(e)?e:p;}
static const char *EA get_log(UN *n){if(n)*n=audit_len;return audit;}
static const char *EA get_value(unsigned i){return i<V_COUNT?values[i]:0;}
static ES EA native_link(void){return native_attach();}
static P1_API api={1,sizeof(P1_API),refresh,get_log,get_value,native_link};
static ES EA unload(HANDLE image){
 (void)image;ES e=native_detach();if(FAILED(e))return e;
 return gST->bs->uninstall_protocol(owner,&service_guid,&api);
}
ES EA efi_main(HANDLE image,ST *system){
 gST=system;if(!gST||!gST->bs||!gST->rt)return ERR(2);void *old=0;
 ES e=gST->bs->locate_protocol(&service_guid,0,&old);if(e!=ERR(14))return FAILED(e)?e:ERR(20);
 logtext("HERO-IPMI-P1 / Native HII class 0014 / reads only\r\nBUILD=P1b-NATIVE-ADVANCED\r\n");
 detect_board();logtext("BOARD ");logtext(report.board);logtext(" BIOS ");logtext(report.bios);logtext("\r\n");
 for(unsigned i=0;i<V_COUNT;i++)value_text(i,"Not queried");
 LOADED *loaded=0;if(FAILED(e=gST->bs->handle_protocol(image,&loaded_guid,(void **)&loaded))||!loaded)return FAILED(e)?e:ERR(14);
 loaded->unload=unload;
 return gST->bs->install_protocol(&owner,&service_guid,0,&api);
}
