#ifndef HERO_NETWORK_R6_H
#define HERO_NETWORK_R6_H
#include "r2.h"
/* Layouts from the pinned EDK II protocol headers in ../reference. */
typedef struct {uint32_t state,hw_size,header_size,max_packet,nv_size,nv_access,filter_mask,filters,max_mcast,mcast_count;uint8_t mcast[16][32],current[32],broadcast[32],permanent[32];uint8_t iftype,changeable,multi_tx,present_supported,present;} SNP_MODE;
typedef struct {uint64_t revision;void *start,*stop,*initialize,*reset,*shutdown,*filters,*station,*statistics,*mcast,*nvdata,*status,*transmit,*receive;HANDLE wait;SNP_MODE *mode;} SNP;
typedef struct SB SB;
struct SB {ES (EA *create)(SB *,HANDLE *);ES (EA *destroy)(SB *,HANDLE);};
typedef struct {uint8_t default_address,address[4],mask[4];uint16_t port;} HTTP4;
typedef struct {uint32_t version,timeout;uint8_t ipv6;HTTP4 *access;} HTTP_CONFIG;
typedef struct {uint32_t method;C16 *url;} HTTP_REQUEST;
typedef struct {uint32_t status;} HTTP_RESPONSE;
typedef struct {char *name,*value;} HTTP_HEADER;
typedef struct {void *data;UN count;HTTP_HEADER *headers;UN length;void *body;} HTTP_MESSAGE;
typedef struct {HANDLE event;ES status;HTTP_MESSAGE *message;} HTTP_TOKEN;
typedef struct HTTP HTTP;
struct HTTP {void *mode;ES (EA *configure)(HTTP *,HTTP_CONFIG *);ES (EA *request)(HTTP *,HTTP_TOKEN *);ES (EA *cancel)(HTTP *,HTTP_TOKEN *);ES (EA *response)(HTTP *,HTTP_TOKEN *);ES (EA *poll)(HTTP *);};
OFF(SNP_MODE,current,552);OFF(SNP_MODE,present,652);OFF(SNP,mode,120);
OFF(HTTP4,port,10);OFF(HTTP_CONFIG,access,16);OFF(HTTP_REQUEST,url,8);
OFF(HTTP_MESSAGE,body,32);OFF(HTTP_TOKEN,message,16);OFF(HTTP,response,32);
_Static_assert(sizeof(HTTP4)==12&&sizeof(HTTP_CONFIG)==24&&sizeof(HTTP_MESSAGE)==40,"network ABI sizes");
int i3_target_valid(void);
int i3_inventory_source_valid(void);
uint64_t i3_inventory_source_epoch(void);
int i3_publication_runtime_ready(void);
void i3_identity_log(void);
void say(const char *);void status(const char *,ES);
void network_inventory(void);
void usb_inventory(void);
int usb_target_handles(HANDLE out[2]);
ES load_network_drivers(HANDLE app,FILEP *root);
ES network_connect(void);
ES network_get(void);
ES network_cleanup(void);
HANDLE network_candidate(void);
ES tcp_connect_probe(void);
ES tcp_cleanup(void);
int tcp_is_active(void);
void tls_inventory(void);
#endif
