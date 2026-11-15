/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{}
*/

undefined4 get_bios_mtd_size(int param_1,__off_t *param_2)

{
  __off_t _Var1;
  
  _Var1 = lseek(param_1,0,2);
  *param_2 = _Var1;
  lseek(param_1,0,0);
  return 0;
}

