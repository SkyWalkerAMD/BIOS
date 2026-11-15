/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "0002cd70": {
    "elf_va": "0x2cd70",
    "file_offset": "0x1cd70",
    "raw_u32": "0x175ac4",
    "target_elf_va": "0x175ac4"
  },
  "0002cd74": {
    "elf_va": "0x2cd74",
    "file_offset": "0x1cd74",
    "raw_u32": "0x147ec0",
    "target_elf_va": "0x147ec0",
    "target_string": "Active Web sessions Termination Initiated.\n"
  },
  "0002cd78": {
    "elf_va": "0x2cd78",
    "file_offset": "0x1cd78",
    "raw_u32": "0x175928",
    "target_elf_va": "0x175928"
  },
  "0002cd7c": {
    "elf_va": "0x2cd7c",
    "file_offset": "0x1cd7c",
    "raw_u32": "0x147e98",
    "target_elf_va": "0x147e98",
    "target_string": "Cannot update active JViewer sessions"
  }
}
*/

void pre_call_hook(void)

{
  int iVar1;
  
  iVar1 = ReadPipeData();
  if (iVar1 < 0) {
    FCGI_fprintf(DAT_0002cd78,DAT_0002cd7c);
  }
  if (*(int *)(DAT_0002cd70 + 0x1e0) != 1) {
    return;
  }
  iVar1 = ReadCmdPipeData();
  if (iVar1 < 1) {
    return;
  }
  FCGI_fprintf(DAT_0002cd78,DAT_0002cd74);
  WebSession_Terminate(iVar1);
  return;
}

