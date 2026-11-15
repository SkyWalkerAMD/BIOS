
void FUN_00010664(void)

{
  undefined1 uVar1;
  int iVar3;
  int iVar4;
  uint extraout_r2;
  undefined4 extraout_r3;
  undefined4 uVar5;
  undefined8 uVar6;
  undefined1 in_stack_00000000;
  undefined4 local_39;
  undefined1 local_35;
  int local_34;
  undefined1 uVar2;
  
  uVar6 = __gnu_mcount_nc();
  iVar3 = (int)uVar6;
  local_35 = 0;
  local_34 = __stack_chk_guard;
  local_39 = 0;
  iVar4 = FUN_00010488();
  if (iVar4 != 0) goto LAB_00010728;
  uVar1 = (undefined1)(extraout_r2 >> 8);
  uVar2 = (undefined1)(extraout_r2 >> 0x10);
  if (DAT_000126c8 == 0) {
    if (0xffffff < extraout_r2) {
      uVar5 = 4;
      goto LAB_000106dc;
    }
    uVar5 = 4;
    local_39._0_2_ = CONCAT11(uVar2,in_stack_00000000);
    local_39._0_3_ = CONCAT12(uVar1,(undefined2)local_39);
    local_39 = CONCAT13((char)extraout_r2,(undefined3)local_39);
  }
  else {
    uVar5 = 5;
LAB_000106dc:
    local_39._0_2_ = CONCAT11((char)(extraout_r2 >> 0x18),in_stack_00000000);
    local_39._0_3_ = CONCAT12(uVar2,(undefined2)local_39);
    local_39 = CONCAT13(uVar1,(undefined3)local_39);
    local_35 = (char)extraout_r2;
  }
  FUN_00010548(iVar3,1);
  (**(code **)(iVar3 + 4))(&local_39,uVar5,(int)((ulonglong)uVar6 >> 0x20),extraout_r3,1);
  FUN_00010488(iVar3);
LAB_00010728:
  if (local_34 != __stack_chk_guard) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

