/* Test carrier only. Production app_require_services is supplied by app.c. */
#include <stdint.h>
#include <stddef.h>
volatile uint32_t boundary_ended,boundary_held,boundary_gate_calls;
__attribute__((noinline,noreturn)) void boundary_hold(void){for(;;)__asm__ volatile("pause");}
void app_require_services(void){boundary_gate_calls++;if(boundary_ended||boundary_held)boundary_hold();}
void *memcpy(void *dst,const void *src,size_t n){uint8_t*d=dst;const uint8_t*s=src;while(n--)*d++=*s++;return dst;}
void *memset(void *dst,int value,size_t n){uint8_t*d=dst;while(n--)*d++=(uint8_t)value;return dst;}
