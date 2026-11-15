#include "settings.h"
/* Generated/checked against this board's 3107 IFR; no Creator offsets. */
const SETTING settings[3]={{"Bootup NumLock State",0,1},{"Wait For F1 If Error",3293,1},{"POST Delay Time (seconds)",3291,10}};
int setting_valid(uint32_t id,uint32_t value){return id<3 && value<=settings[id].maximum;}
int transaction_valid(const TRANSACTION *t){
 if(!t||t->magic!=TX_MAGIC||t->version!=1||t->size!=64||t->setup_size!=SETUP_SIZE||t->attrs!=7||
    !setting_valid(t->setting,t->old_value)||!setting_valid(t->setting,t->new_value)||t->old_value==t->new_value)return 0;
 for(unsigned i=0;i<26;i++)if(t->reserved[i])return 0;
 return t->checksum==probe_crc32(t,offsetof(TRANSACTION,checksum));
}
int prepare_update(const uint8_t *before,size_t size,uint32_t id,uint32_t value,uint32_t expected_crc,uint8_t *after,TRANSACTION *t){
 if(!before||!after||!t||size!=SETUP_SIZE||!setting_valid(id,value)||probe_crc32(before,size)!=expected_crc)return 0;
 uint32_t offset=settings[id].offset;
 if(!setting_valid(id,before[offset])||before[offset]==value)return 0;
 memcpy(after,before,size);after[offset]=(uint8_t)value;memset(t,0,sizeof(*t));
 t->magic=TX_MAGIC;t->version=1;t->size=sizeof(*t);t->setting=id;t->before_crc=expected_crc;
 t->after_crc=probe_crc32(after,size);t->attrs=7;t->setup_size=SETUP_SIZE;t->old_value=before[offset];t->new_value=(uint8_t)value;
 t->checksum=probe_crc32(t,offsetof(TRANSACTION,checksum));return 1;
}
/* 1: restore one byte, 2: already original, 0: refuse changed/invalid state. */
int prepare_restore(const uint8_t *current,size_t size,const TRANSACTION *t,uint8_t *restored){
 if(!current||!restored||size!=SETUP_SIZE||!transaction_valid(t))return 0;
 uint32_t crc=probe_crc32(current,size),off=settings[t->setting].offset;
 if(crc==t->before_crc&&current[off]==t->old_value){memcpy(restored,current,size);return 2;}
 if(crc!=t->after_crc||current[off]!=t->new_value)return 0;
 memcpy(restored,current,size);restored[off]=t->old_value;
 return probe_crc32(restored,size)==t->before_crc?1:0;
}
