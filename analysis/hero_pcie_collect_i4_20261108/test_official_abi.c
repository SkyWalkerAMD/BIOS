/* Compile the original pinned official headers alongside the minimal ABI. */
#include "source/i4_collect.h"
#define IN
#define OUT
#define OPTIONAL
#define EFIAPI EA
#define VOID void
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uint64_t UINTN;
typedef uint8_t BOOLEAN;
typedef uint64_t EFI_STATUS;
typedef uint64_t EFI_LBA;
typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint32_t EFI_ALLOCATE_TYPE;
typedef uint32_t EFI_MEMORY_TYPE;
typedef GUID EFI_GUID;
#include "reference/PciIo.h"
#include "reference/BlockIo.h"
#include "reference/DiskInfo.h"
#define SAME(A,a,B,b) _Static_assert(offsetof(A,a)==offsetof(B,b),"official ABI " #A "." #a)
SAME(EFI_PCI_IO_PROTOCOL,Pci,PCI,pci);
SAME(EFI_PCI_IO_PROTOCOL,GetLocation,PCI,location);
_Static_assert(sizeof(EFI_PCI_IO_PROTOCOL)==sizeof(PCI),"official PCI size");
_Static_assert(EfiPciIoWidthUint8==0,"PCI byte width enum");
SAME(EFI_BLOCK_IO_PROTOCOL,Revision,I4_BLOCK,revision);
SAME(EFI_BLOCK_IO_PROTOCOL,Media,I4_BLOCK,media);
SAME(EFI_BLOCK_IO_PROTOCOL,Reset,I4_BLOCK,reset);
SAME(EFI_BLOCK_IO_PROTOCOL,ReadBlocks,I4_BLOCK,read_blocks);
SAME(EFI_BLOCK_IO_PROTOCOL,WriteBlocks,I4_BLOCK,write_blocks);
SAME(EFI_BLOCK_IO_PROTOCOL,FlushBlocks,I4_BLOCK,flush);
SAME(EFI_BLOCK_IO_MEDIA,MediaId,I4_MEDIA,media_id);
SAME(EFI_BLOCK_IO_MEDIA,RemovableMedia,I4_MEDIA,removable);
SAME(EFI_BLOCK_IO_MEDIA,MediaPresent,I4_MEDIA,present);
SAME(EFI_BLOCK_IO_MEDIA,LogicalPartition,I4_MEDIA,partition);
SAME(EFI_BLOCK_IO_MEDIA,ReadOnly,I4_MEDIA,read_only);
SAME(EFI_BLOCK_IO_MEDIA,WriteCaching,I4_MEDIA,write_cache);
SAME(EFI_BLOCK_IO_MEDIA,BlockSize,I4_MEDIA,block_size);
SAME(EFI_BLOCK_IO_MEDIA,IoAlign,I4_MEDIA,io_align);
SAME(EFI_BLOCK_IO_MEDIA,LastBlock,I4_MEDIA,last_block);
SAME(EFI_BLOCK_IO_MEDIA,LowestAlignedLba,I4_MEDIA,lowest_lba);
SAME(EFI_BLOCK_IO_MEDIA,LogicalBlocksPerPhysicalBlock,I4_MEDIA,logical_per_physical);
SAME(EFI_BLOCK_IO_MEDIA,OptimalTransferLengthGranularity,I4_MEDIA,optimal_transfer);
_Static_assert(sizeof(EFI_BLOCK_IO_MEDIA)==sizeof(I4_MEDIA),"official media size");
SAME(EFI_DISK_INFO_PROTOCOL,Interface,I4_DISK,interface);
SAME(EFI_DISK_INFO_PROTOCOL,Inquiry,I4_DISK,inquiry);
SAME(EFI_DISK_INFO_PROTOCOL,Identify,I4_DISK,identify);
SAME(EFI_DISK_INFO_PROTOCOL,SenseData,I4_DISK,sense);
SAME(EFI_DISK_INFO_PROTOCOL,WhichIde,I4_DISK,which_ide);
_Static_assert(sizeof(EFI_DISK_INFO_PROTOCOL)==sizeof(I4_DISK),"official DiskInfo size");
_Static_assert(EFI_BLOCK_IO_PROTOCOL_REVISION==0x10000&&EFI_BLOCK_IO_PROTOCOL_REVISION2==0x20001&&EFI_BLOCK_IO_PROTOCOL_REVISION3==0x2001f,"official revision gates");
/* Compile the official getter prototype with the minimal integer/calling ABI. */
static ES EA get(EFI_DISK_INFO_PROTOCOL *self,void *b,uint32_t *size){(void)self;(void)b;(void)size;return 0;}
EFI_DISK_INFO_IDENTIFY abi_identify(void){return get;}
