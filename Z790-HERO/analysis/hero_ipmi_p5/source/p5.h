#ifndef HERO_P5_H
#define HERO_P5_H
#include "p1.h"
#define P5_API_GUID {0x6fed589e,0x0b47,0x46b5,{0x82,0xb1,0xdd,0x35,0xd6,0x78,0x59,0xb5}}
typedef struct {
 uint32_t version,size;
 HANDLE image;
 ES (EA *refresh)(void);
 ES (EA *probe)(void);
 const char *(EA *log)(UN *);
 const char *(EA *value)(unsigned);
} P5_API;
ES p5_bind(void);
ES p5_publish(void);
int p5_package_matches(const uint8_t *,UN);
void p5_release(void);
#endif
