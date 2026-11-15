
bool FUN_000130b4(void)

{
  int iVar1;
  undefined1 auStack_34 [4];
  int local_30;
  
  iVar1 = GetVMediaCfg(auStack_34,*(undefined4 *)(DAT_000130f4 + 0x68),
                       *(undefined4 *)(DAT_000130f4 + 0x74),*(undefined4 *)(DAT_000130f4 + 0x180));
  return iVar1 == 0 && local_30 == 1;
}

