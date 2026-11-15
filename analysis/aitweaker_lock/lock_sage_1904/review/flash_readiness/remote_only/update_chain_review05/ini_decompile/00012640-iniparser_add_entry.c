
void iniparser_add_entry(int param_1,int param_2,int param_3,undefined4 param_4)

{
  int iVar1;
  char acStack_41c [1032];
  
  memset(acStack_41c,0,DAT_000126f4);
  if (param_2 != 0 && param_1 != 0) {
    if (param_3 == 0) {
      iniparser_add_section(param_1,param_2);
      return;
    }
    iVar1 = snprintf(acStack_41c,DAT_000126f4,DAT_000126f8,param_2,param_3);
    if (0x400 < iVar1) {
      printf(DAT_00012704,DAT_00012700,0x128,DAT_000126fc);
      return;
    }
    iniparser_setstring(param_1,acStack_41c,param_4);
  }
  return;
}

