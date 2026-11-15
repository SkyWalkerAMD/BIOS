/* ELF literal bindings; Ghidra direct executable VA, no bias.
{
  "00089a2c": {
    "elf_va": "0x89a2c",
    "file_offset": "0x79a2c",
    "raw_u32": "0x16f34c",
    "target_elf_va": "0x16f34c"
  }
}
*/

undefined4 settings_ntp_configuration(void)

{
  undefined4 *puVar1;
  
  puVar1 = DAT_00089a2c;
  add_handler(*DAT_00089a2c);
  add_handler(puVar1[1]);
  add_handler(puVar1[2]);
  return 0;
}

