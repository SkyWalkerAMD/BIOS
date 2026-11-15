
uint FUN_00018c04(void)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = FUN_00018b0c(DAT_00018c34,DAT_00018c30);
  if (iVar1 == -1) {
    return 0xffffffff;
  }
  uVar2 = FUN_000186b4(DAT_00018c38,0);
  return uVar2 & 0xff;
}

