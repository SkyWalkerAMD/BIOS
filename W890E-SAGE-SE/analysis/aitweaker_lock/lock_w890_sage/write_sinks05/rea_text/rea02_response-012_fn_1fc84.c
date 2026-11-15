
bool WS05_1fc84(undefined8 param_1,undefined8 param_2,word *param_3)

{
  undefined8 uVar1;
  bool bVar2;
  
  uVar1 = WS05_1fcb4(0x94348,param_2,param_3);
  bVar2 = (char)uVar1 != '\0';
  if (bVar2) {
    DAT_000afdc8 = 1;
    DAT_000afdc9 = 1;
  }
  return bVar2;
}

