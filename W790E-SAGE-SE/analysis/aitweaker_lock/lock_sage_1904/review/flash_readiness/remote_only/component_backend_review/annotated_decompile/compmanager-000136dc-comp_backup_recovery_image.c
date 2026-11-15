/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00013740": {
    "elf_va": "0x3740",
    "file_offset": "0x3740",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  }
}
*/

void comp_backup_recovery_image(undefined4 param_1,undefined4 param_2)

{
  size_t __n;
  undefined2 uStack_20028;
  undefined1 uStack_20026;
  undefined4 uStack_20024;
  
  __n = DAT_00013740;
  memset(&uStack_20028,0,DAT_00013740);
  memset((void *)((int)&uStack_20028 + __n),0,__n);
  uStack_20028 = 7;
  uStack_20026 = 2;
  uStack_20024 = param_2;
  send_compmngr_command(&uStack_20028,(int)&uStack_20028 + __n,0x3c);
  return;
}

