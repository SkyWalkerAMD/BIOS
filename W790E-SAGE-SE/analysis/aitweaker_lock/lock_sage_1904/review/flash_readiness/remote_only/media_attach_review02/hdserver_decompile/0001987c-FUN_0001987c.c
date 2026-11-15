
void FUN_0001987c(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  
  iVar3 = DAT_000198d4 + 0x19890;
  puVar2 = (undefined4 *)(DAT_000198d8 + 0x19894);
  _DT_INIT();
  iVar3 = iVar3 - (int)puVar2 >> 2;
  if (iVar3 == 0) {
    return;
  }
  iVar1 = 0;
  do {
    iVar1 = iVar1 + 1;
    (*(code *)*puVar2)(param_1,param_2,param_3);
    puVar2 = puVar2 + 1;
  } while (iVar3 != iVar1);
  return;
}

