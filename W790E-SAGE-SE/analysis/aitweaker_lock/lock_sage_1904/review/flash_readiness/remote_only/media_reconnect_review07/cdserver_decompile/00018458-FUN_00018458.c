
uint FUN_00018458(void)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = FUN_00018360(DAT_00018488,DAT_00018484);
  if (iVar1 == -1) {
    return 0xffffffff;
  }
  uVar2 = FUN_00017f08(DAT_0001848c,0);
  return uVar2 & 0xff;
}

