/* ELF literal bindings; Ghidra direct executable VA, no bias.
{
  "0002c8f8": {
    "elf_va": "0x2c8f8",
    "file_offset": "0x1c8f8",
    "raw_u32": "0x1475a0",
    "target_elf_va": "0x1475a0",
    "target_string": "rest.c"
  },
  "0002c8fc": {
    "elf_va": "0x2c8fc",
    "file_offset": "0x1c8fc",
    "raw_u32": "0x2ba",
    "target_elf_va": "0x2ba"
  },
  "0002c900": {
    "elf_va": "0x2c900",
    "file_offset": "0x1c900",
    "raw_u32": "0x147c38",
    "target_elf_va": "0x147c38",
    "target_string": "[%s:%d]Get Command, Time value::%ld\n"
  },
  "0002c904": {
    "elf_va": "0x2c904",
    "file_offset": "0x1c904",
    "raw_u32": "0x7ff",
    "target_elf_va": "0x7ff"
  },
  "0002c908": {
    "elf_va": "0x2c908",
    "file_offset": "0x1c908",
    "raw_u32": "0x147c94",
    "target_elf_va": "0x147c94",
    "target_string": "[%s:%d]Get Command, UTCOffset value::%u\n"
  },
  "0002c90c": {
    "elf_va": "0x2c90c",
    "file_offset": "0x1c90c",
    "raw_u32": "0x2c6",
    "target_elf_va": "0x2c6"
  },
  "0002c910": {
    "elf_va": "0x2c910",
    "file_offset": "0x1c910",
    "raw_u32": "0x175ac4",
    "target_elf_va": "0x175ac4"
  },
  "0002c914": {
    "elf_va": "0x2c914",
    "file_offset": "0x1c914",
    "raw_u32": "0x147b18",
    "target_elf_va": "0x147b18",
    "target_string": "timestamp"
  },
  "0002c918": {
    "elf_va": "0x2c918",
    "file_offset": "0x1c918",
    "raw_u32": "0x147d20",
    "target_elf_va": "0x147d20",
    "target_string": "utc_minutes"
  },
  "0002c91c": {
    "elf_va": "0x2c91c",
    "file_offset": "0x1c91c",
    "raw_u32": "0x147d2c",
    "target_elf_va": "0x147d2c",
    "target_string": "timezone"
  },
  "0002c920": {
    "elf_va": "0x2c920",
    "file_offset": "0x1c920",
    "raw_u32": "0x2b7",
    "target_elf_va": "0x2b7"
  },
  "0002c924": {
    "elf_va": "0x2c924",
    "file_offset": "0x1c924",
    "raw_u32": "0x147c10",
    "target_elf_va": "0x147c10",
    "target_string": "[%s:%d]Error in getting DateTime::%x"
  },
  "0002c928": {
    "elf_va": "0x2c928",
    "file_offset": "0x1c928",
    "raw_u32": "0x2d2",
    "target_elf_va": "0x2d2"
  },
  "0002c92c": {
    "elf_va": "0x2c92c",
    "file_offset": "0x1c92c",
    "raw_u32": "0x147cf4",
    "target_elf_va": "0x147cf4",
    "target_string": "[%s:%d]Get Command, Timezone value is::%s\n"
  },
  "0002c930": {
    "elf_va": "0x2c930",
    "file_offset": "0x1c930",
    "raw_u32": "0x2bf",
    "target_elf_va": "0x2bf"
  },
  "0002c934": {
    "elf_va": "0x2c934",
    "file_offset": "0x1c934",
    "raw_u32": "0x147c60",
    "target_elf_va": "0x147c60",
    "target_string": "[%s:%d]Error in getting SEL UTC Offset value::%x"
  },
  "0002c938": {
    "elf_va": "0x2c938",
    "file_offset": "0x1c938",
    "raw_u32": "0x2ce",
    "target_elf_va": "0x2ce"
  },
  "0002c93c": {
    "elf_va": "0x2c93c",
    "file_offset": "0x1c93c",
    "raw_u32": "0x147cc0",
    "target_elf_va": "0x147cc0",
    "target_string": "[%s:%d]Error in getting Timezone configuration::%x\n"
  }
}
*/

int webGetDateTime(undefined4 param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 uVar2;
  size_t sVar3;
  undefined4 uVar4;
  uint3 local_dc;
  undefined1 uStack_d9;
  uint local_d8;
  byte local_d4;
  undefined1 auStack_d0 [64];
  char acStack_90 [128];
  
  memset(acStack_90,0,0x80);
  iVar1 = IPMICMD_GetSELTime(param_1,&local_d8,0x1e);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0002c924,DAT_0002c8f8,DAT_0002c920,iVar1);
    return iVar1;
  }
  IDBG_LINUXAPP_Runtime_DbgOut
            (0x87,DAT_0002c900,DAT_0002c8f8,DAT_0002c8fc,(uint)local_d4 << 0x18 | local_d8 >> 8);
  iVar1 = IPMICMD_GetSELTimeUTCOffset(param_1,&local_dc,0x1e);
  if (iVar1 == 0) {
    iVar1 = (_local_dc << 8) >> 0x10;
    if (iVar1 == DAT_0002c904) {
      local_dc = (uint3)(byte)local_dc;
      iVar1 = 0;
    }
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_0002c908,DAT_0002c8f8,DAT_0002c90c,iVar1);
    if (*(int *)(DAT_0002c910 + 0x140) == 1) {
      memset(auStack_d0,0,0x40);
      iVar1 = LIBIPMI_HL_AMIGetTimeZone(param_1,auStack_d0,0x1e);
      if (iVar1 != 0) {
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_0002c93c,DAT_0002c8f8,DAT_0002c938,iVar1);
        return iVar1;
      }
      Escaper(auStack_d0,acStack_90);
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_0002c92c,DAT_0002c8f8,DAT_0002c928,acStack_90);
    }
    uVar4 = *param_2;
    uVar2 = json_object_new_int((uint)local_d4 << 0x18 | local_d8 >> 8);
    json_object_object_add(uVar4,DAT_0002c914,uVar2);
    uVar4 = *param_2;
    uVar2 = json_object_new_int((_local_dc << 8) >> 0x10);
    json_object_object_add(uVar4,DAT_0002c918,uVar2);
    sVar3 = strlen(acStack_90);
    uVar4 = *param_2;
    uVar2 = json_object_new_string_len(acStack_90,sVar3);
    json_object_object_add(uVar4,DAT_0002c91c,uVar2);
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_0002c934,DAT_0002c8f8,DAT_0002c930,iVar1);
  return iVar1;
}

