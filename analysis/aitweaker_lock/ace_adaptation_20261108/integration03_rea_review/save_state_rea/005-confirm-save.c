
char Candidate_ACE_ConfirmSave(undefined8 param_1,undefined1 param_2)

{
  char cVar1;
  longlong lVar2;
  undefined8 local_res18;
  undefined8 local_48 [3];
  uint local_2c;
  undefined8 local_20;
  
  local_res18 = 0;
  cVar1 = -1;
  lVar2 = (*(code *)PTR_FUN_0006b090)(&local_res18);
  if (-1 < lVar2) {
    FUN_00000360(local_48,0x40,0);
    local_48[0] = 0xffffffffffffffff;
    local_2c = local_2c | 1;
    local_20 = param_1;
    lVar2 = (*(code *)PTR_FUN_0006b0a0)(local_res18,local_48);
    if (-1 < lVar2) {
      (*(code *)PTR_FUN_0006b0e8)(local_res18,param_2);
      cVar1 = FUN_00019fac(local_res18);
    }
    (*(code *)PTR_FUN_0006b098)(local_res18,1);
  }
  return cVar1;
}

