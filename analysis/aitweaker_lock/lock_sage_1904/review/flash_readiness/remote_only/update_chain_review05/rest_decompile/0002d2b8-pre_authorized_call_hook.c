
void pre_authorized_call_hook(undefined4 param_1,int param_2)

{
  int iVar1;
  
  qcgisess_getid(param_2);
  iVar1 = getViewerCount();
  if (0 < iVar1) {
                    /* WARNING: Could not recover jumptable at 0x0002d2f0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(param_2 + 0xc))(param_2,DAT_0002d314,1);
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x0002d310. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(param_2 + 0xc))(param_2,DAT_0002d314,0,1);
  return;
}

