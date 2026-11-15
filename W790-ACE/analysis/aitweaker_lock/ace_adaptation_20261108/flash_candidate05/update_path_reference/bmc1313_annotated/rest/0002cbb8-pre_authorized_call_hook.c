/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "0002cc14": {
    "elf_va": "0x2cc14",
    "file_offset": "0x1cc14",
    "raw_u32": "0x147e5c",
    "target_elf_va": "0x147e5c",
    "target_string": "DO_NOT_DESTROY"
  }
}
*/

void pre_authorized_call_hook(undefined4 param_1,int param_2)

{
  int iVar1;
  
  qcgisess_getid(param_2);
  iVar1 = getViewerCount();
  if (0 < iVar1) {
                    /* WARNING: Could not recover jumptable at 0x0002cbf0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(param_2 + 0xc))(param_2,DAT_0002cc14,1);
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x0002cc10. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(param_2 + 0xc))(param_2,DAT_0002cc14,0,1);
  return;
}

