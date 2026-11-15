
void FUN_00000944(void)

{
  longlong lVar1;
  
  if (DAT_00001217 != '\0') {
    FUN_00000708(DAT_000011f0,1);
  }
  if (DAT_0000121a != '\0') {
    lVar1 = FUN_00000f9c();
    (**(code **)(lVar1 + 0xa0))(0x214,1);
    FUN_00000708(DAT_000011f0,3);
  }
  return;
}

