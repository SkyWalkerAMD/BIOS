/****************************************************************
 ****************************************************************
 **                                                            **
 **    (C)Copyright 2002-2018, American Megatrends Inc.        **
 **                                                            **
 **            All Rights Reserved.                            **
 **                                                            **
 **        5555, Oakbrook Parkway, Suite 200, Norcross,        **
 **                                                            **
 **        Georgia - 30093, USA. Phone-(770)-246-8600.         **
 **                                                            **
 ****************************************************************
 ****************************************************************/
/*****************************************************************
 *
 * HPM_Conf.h
 * HPM configuration related headers
 *
 *****************************************************************/
/*----------------------------------------------------------*
 * Pre-defined or fixed configurations
 *----------------------------------------------------------*/
 
#include "IPMIDefs.h"
#include "HPMCmds.h"
#include "IPMI_HPMCmds.h"
#include "HPMFuncs.h"
#include "HPM.h"
#include "fmh.h"
#include "iniparser.h"
#include <dbgout.h>
#include "unix.h"
#include "compmngrhelper.h"
#include "IPMI_IPM.h"
#include <dlfcn.h>
#include "string.h"
#include "flashlib.h"
#include "PDKAccess.h"

/* Variable upgrade information about ID, size, and offsets */
#define OEM_HEADER_PRE_ALLOC_SIZE 12
#define UBOOT_SIZE              (CONFIG_SPX_FEATURE_GLOBAL_UBOOT_ENV_START - CONFIG_SPX_FEATURE_GLOBAL_FLASH_START)
#define BOOT_COMPONENT_SIZE     (UBOOT_SIZE + CONFIG_SPX_FEATURE_GLOBAL_UBOOT_ENV_SIZE)
#define APP_COMPONENT_OFFSET    BOOT_COMPONENT_SIZE
#define APP_COMPONENT_SIZE      (CONFIG_SPX_FEATURE_GLOBAL_USED_FLASH_SIZE - APP_COMPONENT_OFFSET)
#define BOOT_COMPONENT_MAX_BUFFER 0x100000
ComponentFlashInfo_T ComponentFlashInfoTbl[MAX_COMPONENTS] =
{
    /* Memoffset, Flashoffset, Sizetocpy, AllocateMemSize, DescString */
    { 0x0,     0x0,                  UBOOT_SIZE,         (BOOT_COMPONENT_SIZE + OEM_HEADER_PRE_ALLOC_SIZE), { 'B','O','O','T' } },
    { 0x0,     APP_COMPONENT_OFFSET, APP_COMPONENT_SIZE, (APP_COMPONENT_SIZE + OEM_HEADER_PRE_ALLOC_SIZE),  { 'A','P', 'P' }    },
    { 0x0,     0x0,                  0x0,                0x0,                                               { 'B','I','O','S' } },
    { 0x0,     0x0,                  0x0,                0x0,                                               { 'M','M','C' }     },
    { 0x0,     0x0,                  0x0,                0x0,                                               { 'M','E' }         },
    { 0x0,     0x0,                  0x0,                0x0,                                               { 'C','P','L','D' } },
    { 0x0,     0x0,                  0x0,                0x0,                                               { 'A','E','P' } },
    { 0x0,     0x0,                  0x0,                0x0,                                               { 'R','A','I','D','-','M','S','C','C' } }
};

INT8U ValidComponentIDTbl[MAX_COMPONENTS] = { 1, 1, 1, 1, 1, 1, 1, 1 };

/* static variables */
HPMConfTargetCap_T HPMConfTargetCap;
HPMConfCompProp_T HPMConfCompPropTbl[MAX_COMPONENTS];
BOOL FwVersionCachedTbl[MAX_COMPONENTS][FWVER_TYPE_MAX];
