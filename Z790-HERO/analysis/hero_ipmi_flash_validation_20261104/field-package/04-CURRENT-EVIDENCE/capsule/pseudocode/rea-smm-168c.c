
/* WARNING: Type propagation algorithm not settling */

void FUN_0000168c(longlong param_1)

{
  longlong lVar1;
  undefined *puVar2;
  longlong lVar3;
  longlong local_res8 [4];
  char local_28 [32];
  
  if (((DAT_000051a0 & 2) != 0) || ((DAT_000051a1 & 2) != 0)) {
    local_res8[1] = 0x1d;
    local_res8[0] = param_1;
    lVar1 = (**(code **)(DAT_00005820 + 0x48))
                      (u_AmiFlashUpd_000052f8,&DAT_000051d8,0,local_res8 + 1,local_28);
    lVar3 = DAT_00005820;
    if ((-1 < lVar1) && (local_28[0] == '\x02')) {
      local_res8[1] = 8;
      puVar2 = FUN_000015d4();
      lVar3 = (**(code **)(lVar3 + 0x48))(puVar2,&DAT_00005150,0,local_res8 + 1,local_res8);
      if ((-1 < lVar3) && (local_res8[0] == DAT_000057d8)) {
        lVar3 = FUN_00004650(*(longlong **)(local_res8[0] + 8),(longlong *)&DAT_000050b0,0x10);
        if (lVar3 == 0) {
          FUN_000046c8();
        }
      }
    }
  }
  return;
}

