/* Explicit, once-per-boot RAM driver load. Native USB binding, no SPI writes.
 * Retain the donor boot-mode gates. The application replaces its board-specific
 * IPMI feature gate with exact HERO 3107 / observed 046b:ffb0 interface checks.
 * The original drivers lack unload support; reset removes this test session.
 */
#include "network.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID marker_guid={0x685d3af0,0x41d9,0x46e6,{0xa7,0x37,0x2a,0x04,0x78,0x50,0x6c,0xa8}};
typedef struct {uint32_t magic,state;HANDLE drivers[3];} LOAD_STATE;
uint32_t probe_crc32(const void *,size_t);
static ES load_one(HANDLE app,FILEP *root,C16 *name,UN expected,uint32_t crc,HANDLE *child){
 FILEP *f=0;ES e=root->open(root,&f,name,1,0);if(FAILED(e)||!f)return FAILED(e)?e:ERR(14);
 uint8_t *bytes=0;UN n=16384;e=gST->bs->allocate_pool(4,n,(void **)&bytes);if(FAILED(e)){f->close(f);return e;}
 e=f->read(f,&n,bytes);f->close(f);if(FAILED(e)||n!=expected||probe_crc32(bytes,n)!=crc){gST->bs->free_pool(bytes);return FAILED(e)?e:ERR(33);}
 e=gST->bs->load_image(0,app,0,bytes,n,child);gST->bs->free_pool(bytes);status("NETWORK_MODULE_LOAD_IMAGE",e);if(FAILED(e))return e;
 LOADED *li=0;e=gST->bs->handle_protocol(*child,&loaded_guid,(void **)&li);
 if(FAILED(e)||!li){gST->bs->unload_image(*child);return FAILED(e)?e:ERR(14);}
 e=gST->bs->start_image(*child,0,0);status("NETWORK_MODULE_START_IMAGE",e);return e;
}
ES load_network_drivers(HANDLE app,FILEP *root){
 HANDLE usb[2];if(!root||!usb_target_handles(usb))return ERR(15);
 LOAD_STATE *old=0;ES e=gST->bs->locate_protocol(&marker_guid,0,(void **)&old);if(e!=ERR(14))return ERR(20);
 LOAD_STATE *state=0;e=gST->bs->allocate_pool(4,sizeof(*state),(void **)&state);if(FAILED(e))return e;
 memset(state,0,sizeof(*state));state->magic=0x364e5348;HANDLE marker=0;
 e=gST->bs->install_protocol(&marker,&marker_guid,0,state);if(FAILED(e)){gST->bs->free_pool(state);return e;}
 /* Keep this passive marker and driver handles until reset, even on error.
  * No pointer into application code survives application exit. */
 state->state=1;
 e=load_one(app,root,W("\\EFI\\BOOT\\H6RNDIS.EFI"),10112,0x9afc71b7,&state->drivers[0]);if(FAILED(e))return e;
 e=load_one(app,root,W("\\EFI\\BOOT\\H6USBLAN.EFI"),12256,0xf43ee32c,&state->drivers[1]);if(FAILED(e))return e;
 state->state=2;
 ES (EA *connect)(HANDLE,HANDLE *,void *,uint8_t)=(void *)gST->bs->connect;
 for(unsigned i=0;i<2;i++){e=connect(usb[i],state->drivers,0,1);status(i?"CONNECT_RNDIS_DATA":"CONNECT_RNDIS_CONTROL",e);}
 for(unsigned i=0;i<2;i++){e=connect(usb[i],0,0,1);status(i?"CONNECT_STANDARD_DATA_STACK":"CONNECT_STANDARD_CONTROL_STACK",e);}
 state->state=3;logtext("NETWORK_RAM_DRIVERS_RETAINED_UNTIL_RESET\r\n");return 0;
}
