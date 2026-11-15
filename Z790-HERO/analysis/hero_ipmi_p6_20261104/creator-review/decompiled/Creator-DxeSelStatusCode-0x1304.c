
void SelBootCallback_from_CreateEvent(longlong param_1)

{
  longlong lVar1;
  ulonglong uVar2;
  wchar_t *pwVar3;
  undefined7 uVar4;
  undefined *puVar5;
  undefined4 local_res18 [2];
  undefined8 local_res20;
  undefined1 local_278 [29];
  undefined4 local_25b;
  
  lVar1 = (**(code **)(DAT_000020a0 + 0x140))(&DAT_00002010,0,&DAT_00002110);
  if (-1 < lVar1) {
    local_res20 = 0x267;
    puVar5 = &DAT_00002020;
    pwVar3 = u_ServerSetup_00002050;
    lVar1 = (**(code **)(DAT_000020a8 + 0x48))
                      (u_ServerSetup_00002050,&DAT_00002020,local_res18,&local_res20,local_278);
    uVar4 = (undefined7)((ulonglong)pwVar3 >> 8);
    if (lVar1 < 0) {
      pwVar3 = (wchar_t *)CONCAT71(uVar4,1);
      local_25b = 0x2000001;
      local_25b._1_1_ = '\0';
    }
    else {
      pwVar3 = (wchar_t *)CONCAT71(uVar4,(byte)local_25b);
    }
    if ((char)pwVar3 != '\0') {
      if ((byte)(local_25b._1_1_ - 1U) < 2) {
        FUN_0000168c(pwVar3);
        if (local_25b._1_1_ == '\x01') {
          puVar5 = &DAT_00002020;
          pwVar3 = u_ServerSetup_00002050;
          local_25b._0_2_ = (ushort)(byte)local_25b;
          (**(code **)(DAT_000020a8 + 0x58))
                    (u_ServerSetup_00002050,&DAT_00002020,local_res18[0],local_res20,local_278);
        }
      }
      DAT_00002118 = local_25b._2_1_;
      uVar2 = FUN_00001624(pwVar3,puVar5);
      if (((char)uVar2 == '\x01') && (DAT_00002118 == '\x01')) {
        FUN_0000168c(pwVar3);
      }
    }
  }
  if (param_1 != 0) {
    (**(code **)(DAT_000020a0 + 0x70))(param_1);
  }
  return;
}

