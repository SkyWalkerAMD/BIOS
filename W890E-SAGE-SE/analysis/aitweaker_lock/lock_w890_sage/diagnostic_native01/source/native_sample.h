/* Read-only structural sample, never an authorization or ownership proof. */
#ifndef W890_NATIVE_SAMPLE_H
#define W890_NATIVE_SAMPLE_H
#include <stdint.h>
#include <stddef.h>
#ifdef NS_EXPORT
#define NS_API __declspec(dllexport)
#else
#define NS_API
#endif
typedef int (*NS_COPY)(void *,uint64_t,void *,size_t);
typedef struct {
 uint64_t app,stage,boot_services,string_hii,history;
 uint32_t history_root,history_capacity,history_count,reserved;
} NS_GLOBALS;
typedef struct {
 NS_GLOBALS globals;
 uint64_t page_array,page,hii,frames,extras;
 uint32_t current_index,page_count,menu_mode,frame_count,extra_count;
 uint16_t form,index,parent;
 uint8_t redraw,exit_flag,page_flags,reserved;
} NS_SAMPLE;
enum {NS_OK=0,NS_INACTIVE=1,NS_BAD_IMAGE=2,NS_GLOBAL_READ=3,NS_APP_READ=4,
 NS_APP_BOUNDS=5,NS_PAGE_READ=6,NS_PAGE_BOUNDS=7,NS_CHANGED=8};
NS_API int ns_range(const void *map,size_t bytes,size_t stride,uint32_t version,uint64_t address,size_t length);
NS_API int ns_sample(NS_COPY,void *,uint64_t base,size_t image_bytes,NS_SAMPLE *);
#endif
