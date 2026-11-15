/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "0002a7d0": {
    "elf_va": "0x2a7d0",
    "file_offset": "0x1a7d0",
    "raw_u32": "0x1473bc",
    "target_elf_va": "0x1473bc",
    "target_string": "/conf/web_features/"
  },
  "0002a7d4": {
    "elf_va": "0x2a7d4",
    "file_offset": "0x1a7d4",
    "raw_u32": "0x150540",
    "target_elf_va": "0x150540",
    "target_string": "%s%s"
  },
  "0002a7d8": {
    "elf_va": "0x2a7d8",
    "file_offset": "0x1a7d8",
    "raw_u32": "0x14ed38",
    "target_elf_va": "0x14ed38",
    "target_string": "r"
  },
  "0002a7dc": {
    "elf_va": "0x2a7dc",
    "file_offset": "0x1a7dc",
    "raw_u32": "0x147408",
    "target_elf_va": "0x147408",
    "target_string": "%ld"
  },
  "0002a7e0": {
    "elf_va": "0x2a7e0",
    "file_offset": "0x1a7e0",
    "raw_u32": "0x17a",
    "target_elf_va": "0x17a"
  },
  "0002a7e4": {
    "elf_va": "0x2a7e4",
    "file_offset": "0x1a7e4",
    "raw_u32": "0x147198",
    "target_elf_va": "0x147198",
    "target_string": "helper.c"
  },
  "0002a7e8": {
    "elf_va": "0x2a7e8",
    "file_offset": "0x1a7e8",
    "raw_u32": "0x1473d0",
    "target_elf_va": "0x1473d0",
    "target_string": "[%s:%d]getWebFeatureInt - flock is failed with LOCK_EX\n"
  }
}
*/

undefined4 getWebFeatureInt(undefined4 param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 local_94;
  char acStack_90 [132];
  
  local_94 = 0;
  memset(acStack_90,0,0x80);
  createIfNotExists(DAT_0002a7d0);
  snprintf(acStack_90,0x80,DAT_0002a7d4,DAT_0002a7d0,param_1);
  puVar1 = (undefined4 *)FCGI_fopen(acStack_90,DAT_0002a7d8);
  if (puVar1 != (undefined4 *)0x0) {
    uVar2 = FCGI_fileno();
    iVar3 = sigwrap_flock(uVar2,2);
    if (iVar3 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0002a7e8,DAT_0002a7e4,DAT_0002a7e0);
      FCGI_fclose(puVar1);
      local_94 = 0xffffffff;
    }
    else {
      __isoc99_fscanf(*puVar1,DAT_0002a7dc,&local_94);
      uVar2 = FCGI_fileno(puVar1);
      sigwrap_flock(uVar2,8);
      FCGI_fclose(puVar1);
    }
  }
  return local_94;
}

