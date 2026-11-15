/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_000136d8": {
    "elf_va": "0x36d8",
    "file_offset": "0x36d8",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  }
}
*/

void comp_perform_bios_recovery(undefined4 param_1)

{
  size_t __n;
  undefined2 uStack_20028;
  undefined1 uStack_20026;
  undefined4 uStack_20024;
  
  __n = DAT_000136d8;
  memset(&uStack_20028,0,DAT_000136d8);
  memset((void *)((int)&uStack_20028 + __n),0,__n);
  uStack_20028 = 8;
  uStack_20026 = 2;
  uStack_20024 = param_1;
  send_compmngr_command(&uStack_20028,(int)&uStack_20028 + __n,0x3c);
  return;
}

