
void FUN_0003d204(void)

{
  longlong lVar1;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_18 = 0x71202eee;
  local_14 = 0x40d95f53;
  local_10 = 0xc9e3dab;
  local_c = 0x5766d926;
  if (DAT_001908a0 == 0) {
    FUN_0000176c(&local_18);
    DAT_001908a0 = 1;
    lVar1 = 0xffff0003;
    FUN_00003c38(0xffff0003,&LAB_0004b2c8);
    if (DAT_001801a0 - 4U < 2) {
      FUN_000b467c(lVar1);
    }
    FUN_0000176c(&local_18);
    FUN_000b1c80(1,0x3050007);
  }
  return;
}

