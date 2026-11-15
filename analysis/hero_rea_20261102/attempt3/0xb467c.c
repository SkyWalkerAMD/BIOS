
void FUN_000b467c(longlong param_1)

{
  undefined8 *puVar1;
  longlong lVar2;
  int iVar3;
  longlong local_res8;
  undefined1 local_res10 [8];
  
  puVar1 = DAT_001807b8;
  iVar3 = 0;
  local_res8 = param_1;
  lVar2 = (**(code **)(DAT_00180188 + 0x40))(4,0x24,&local_res8);
  do {
    if (lVar2 < 0) {
LAB_000b46db:
      (**(code **)(DAT_00180188 + 0x48))(local_res8);
      return;
    }
    lVar2 = (*(code *)*puVar1)(puVar1,iVar3,local_res10,&local_res8);
    if (*(int *)(local_res8 + 4) == 0x400) {
      (*(code *)puVar1[1])(puVar1,iVar3);
      goto LAB_000b46db;
    }
    iVar3 = iVar3 + 1;
  } while( true );
}

