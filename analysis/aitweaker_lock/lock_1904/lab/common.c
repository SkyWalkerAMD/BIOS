#include "lab.h"
void *memset(void*p,int c,size_t n){uint8_t*b=p;while(n--)*b++=(uint8_t)c;return p;}
void *memcpy(void*p,const void*s,size_t n){uint8_t*a=p;const uint8_t*b=s;while(n--)*a++=*b++;return p;}
ES start_file(ST*st,HANDLE self,C16*name,HANDLE*child){
 LOADED*li=0;uint8_t*dp=0;ES e=st->bs->handle_protocol(self,&loaded_guid,(void**)&li);if(e||!li)return ERR(7);
 e=st->bs->handle_protocol(li->device,&dp_guid,(void**)&dp);if(e||!dp)return ERR(7);
 UN p=0,n=0;while(name[n])n++;n=(n+1)*2;
 while(p+4<=2048){UN k=dp[p+2]+((UN)dp[p+3]<<8);if(k<4||k>2048-p)return ERR(33);if(dp[p]==0x7f)break;p+=k;}
 if(p+4>2048||n>512)return ERR(33);
 uint8_t*path=0;e=st->bs->allocate_pool(4,p+4+n+4,(void**)&path);if(e)return e;
 memcpy(path,dp,p);path[p]=4;path[p+1]=4;path[p+2]=(uint8_t)(4+n);path[p+3]=(uint8_t)((4+n)>>8);memcpy(path+p+4,name,n);
 uint8_t end[]={0x7f,0xff,4,0};memcpy(path+p+4+n,end,4);
 e=((LOAD_IMAGE)st->bs->load_image)(0,self,path,0,0,child);st->bs->free_pool(path);if(e)return e;
 UN exn=0;C16*ex=0;e=((START_IMAGE)st->bs->start_image)(*child,&exn,&ex);if(ex)st->bs->free_pool(ex);return e;
}
