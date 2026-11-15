
bool FUN_00012e7c(void)

{
  int iVar1;
  int local_34 [12];
  
  iVar1 = GetVMediaCfg(local_34,*(undefined4 *)(DAT_00012ebc + 0x68),
                       *(undefined4 *)(DAT_00012ebc + 0x74),*(undefined4 *)(DAT_00012ebc + 0x180));
  return iVar1 == 0 && local_34[0] == 1;
}

