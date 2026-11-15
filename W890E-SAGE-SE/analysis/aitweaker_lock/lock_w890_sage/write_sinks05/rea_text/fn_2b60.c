
void WS05_2b60(void)

{
  char cVar1;
  undefined8 uVar2;
  longlong lVar3;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res20 = 0;
  local_res18 = 0;
  uVar2 = (**(code **)(DAT_0001c0d8 + 0x18))(0x1f);
  (**(code **)(DAT_0001c0d8 + 0x20))(4);
  lVar3 = (**(code **)(DAT_0001c0d8 + 0x140))(&DAT_000193a8,0,&local_res18);
  if (lVar3 < 0) {
    (**(code **)(DAT_0001c0d8 + 0x18))(0x1f);
  }
  else {
    FUN_0000fec0();
    cVar1 = FUN_00005f98(&DAT_00019358,3);
    if (cVar1 == '\x01') {
      FUN_000018c0(1);
    }
    FUN_0000fec0();
    if (DAT_0001c1b8 != 0) {
      (**(code **)(DAT_0001c1b8 + 0x18))(&local_res20);
    }
    (**(code **)(DAT_0001c0d8 + 0x18))(0x1f);
  }
  (**(code **)(DAT_0001c0d8 + 0x20))(uVar2);
  return;
}

