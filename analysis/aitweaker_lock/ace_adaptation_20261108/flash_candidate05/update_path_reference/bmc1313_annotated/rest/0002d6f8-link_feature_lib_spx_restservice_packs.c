/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "0002d7b4": {
    "elf_va": "0x2d7b4",
    "file_offset": "0x1d7b4",
    "raw_u32": "0x16daa8",
    "target_elf_va": "0x16daa8"
  },
  "0002d7b8": {
    "elf_va": "0x2d7b8",
    "file_offset": "0x1d7b8",
    "raw_u32": "0x1475a0",
    "target_elf_va": "0x1475a0",
    "target_string": "rest.c"
  },
  "0002d7bc": {
    "elf_va": "0x2d7bc",
    "file_offset": "0x1d7bc",
    "raw_u32": "0x1480c4",
    "target_elf_va": "0x1480c4",
    "target_string": "[%s:%d]Error in loading function not library"
  },
  "0002d7c0": {
    "elf_va": "0x2d7c0",
    "file_offset": "0x1d7c0",
    "raw_u32": "0x148088",
    "target_elf_va": "0x148088",
    "target_string": "[%s:%d]Error in loading libspx res service feature library"
  },
  "0002d7c4": {
    "elf_va": "0x2d7c4",
    "file_offset": "0x1d7c4",
    "raw_u32": "0x1002",
    "target_elf_va": "0x1002"
  },
  "0002d7c8": {
    "elf_va": "0x2d7c8",
    "file_offset": "0x1d7c8",
    "raw_u32": "0x663",
    "target_elf_va": "0x663"
  },
  "0002d7cc": {
    "elf_va": "0x2d7cc",
    "file_offset": "0x1d7cc",
    "raw_u32": "0x668",
    "target_elf_va": "0x668"
  }
}
*/

undefined4 link_feature_lib_spx_restservice_packs(void)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  code *pcVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  
  uVar3 = DAT_0002d7c0;
  uVar2 = DAT_0002d7bc;
  uVar1 = DAT_0002d7b8;
  puVar7 = DAT_0002d7b4 + 0x41;
  puVar6 = DAT_0002d7b4;
  do {
    iVar4 = IsFeatureEnabled(*puVar6);
    if (iVar4 != 0) {
      iVar4 = dlopen(puVar6[1],DAT_0002d7c4);
      puVar6[4] = iVar4;
      if (iVar4 == 0) {
        IDBG_LINUXAPP_DbgOut(0x82,uVar3,uVar1,DAT_0002d7c8);
      }
      else {
        pcVar5 = (code *)dlsym(iVar4,puVar6[2]);
        puVar6[3] = pcVar5;
        if (pcVar5 == (code *)0x0) {
          IDBG_LINUXAPP_DbgOut(0x82,uVar2,uVar1,DAT_0002d7cc);
          dlclose(puVar6[4]);
        }
        else {
          (*pcVar5)();
          dlclose(puVar6[4]);
        }
      }
    }
    puVar6 = puVar6 + 5;
  } while (puVar6 != puVar7);
  return 0;
}

