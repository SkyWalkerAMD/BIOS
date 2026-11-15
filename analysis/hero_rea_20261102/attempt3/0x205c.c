
void FUN_0000205c(void)

{
  ulonglong uVar1;
  ulonglong uVar2;
  ulonglong local_res8;
  ulonglong local_res10;
  
  local_res8 = 0;
  local_res10 = 0;
  if (DAT_00180200 != 0) {
    FUN_0000931c(&local_res8,&local_res10);
  }
  uVar2 = local_res10;
  uVar1 = local_res8;
  if (DAT_001938c0 != 0) {
    FUN_000013d0(&DAT_001938c0);
  }
  DAT_001938c0 = FUN_000014c8(uVar2 * uVar1 * 4);
  if ((DAT_001938c0 != 0) && (DAT_00180200 != 0)) {
    (**(code **)(DAT_00180200 + 0x10))(DAT_00180200,DAT_001938c0,1,0,0,0,0,uVar1,uVar2,0);
  }
  return;
}

