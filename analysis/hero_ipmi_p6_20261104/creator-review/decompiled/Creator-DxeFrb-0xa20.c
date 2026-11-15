
void FUN_00000a20(void)

{
  longlong lVar1;
  
  lVar1 = FUN_00000f9c();
                    /* WARNING: Could not recover jumptable at 0x00000a34. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(lVar1 + 0xa0))(0x214,0);
  return;
}

