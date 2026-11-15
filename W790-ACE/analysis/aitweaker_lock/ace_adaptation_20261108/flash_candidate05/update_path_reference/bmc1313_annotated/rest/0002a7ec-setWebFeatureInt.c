/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "0002a8b8": {
    "elf_va": "0x2a8b8",
    "file_offset": "0x1a8b8",
    "raw_u32": "0x1473bc",
    "target_elf_va": "0x1473bc",
    "target_string": "/conf/web_features/"
  },
  "0002a8bc": {
    "elf_va": "0x2a8bc",
    "file_offset": "0x1a8bc",
    "raw_u32": "0x150540",
    "target_elf_va": "0x150540",
    "target_string": "%s%s"
  },
  "0002a8c0": {
    "elf_va": "0x2a8c0",
    "file_offset": "0x1a8c0",
    "raw_u32": "0x156448",
    "target_elf_va": "0x156448",
    "target_string": "w"
  },
  "0002a8c4": {
    "elf_va": "0x2a8c4",
    "file_offset": "0x1a8c4",
    "raw_u32": "0x147408",
    "target_elf_va": "0x147408",
    "target_string": "%ld"
  },
  "0002a8c8": {
    "elf_va": "0x2a8c8",
    "file_offset": "0x1a8c8",
    "raw_u32": "0x147198",
    "target_elf_va": "0x147198",
    "target_string": "helper.c"
  },
  "0002a8cc": {
    "elf_va": "0x2a8cc",
    "file_offset": "0x1a8cc",
    "raw_u32": "0x14740c",
    "target_elf_va": "0x14740c",
    "target_string": "[%s:%d] setWebFeatureInt - Failed in flock with LOCK_UN\n"
  }
}
*/

undefined4 setWebFeatureInt(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  char acStack_90 [128];
  
  memset(acStack_90,0,0x80);
  createIfNotExists(DAT_0002a8b8);
  snprintf(acStack_90,0x80,DAT_0002a8bc,DAT_0002a8b8,param_1);
  iVar1 = FCGI_fopen(acStack_90,DAT_0002a8c0);
  if (iVar1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    uVar2 = FCGI_fileno();
    sigwrap_flock(uVar2,2);
    FCGI_fprintf(iVar1,DAT_0002a8c4,param_2);
    uVar2 = FCGI_fileno(iVar1);
    iVar3 = sigwrap_flock(uVar2,8);
    if (iVar3 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0002a8cc,DAT_0002a8c8,0x198);
      FCGI_fclose(iVar1);
      uVar2 = 0xffffffff;
    }
    else {
      FCGI_fclose(iVar1);
      uVar2 = 0;
    }
  }
  return uVar2;
}

