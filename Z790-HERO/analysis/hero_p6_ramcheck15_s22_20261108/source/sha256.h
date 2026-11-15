#ifndef LC_SHA256_H
#define LC_SHA256_H
#include <stdint.h>
#include <stddef.h>
void ap_sha256(const uint8_t*,size_t,uint8_t[32]);
void ap_secure_zero(void*,size_t);
int ap_constant_equal(const void*,const void*,size_t);
#endif
