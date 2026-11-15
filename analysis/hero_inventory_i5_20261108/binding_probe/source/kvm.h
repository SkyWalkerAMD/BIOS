#ifndef KVM_H
#define KVM_H
#include "efi_min.h"
ES kvm_present(ST *table,const char *log,size_t length,unsigned warnings);
#endif
