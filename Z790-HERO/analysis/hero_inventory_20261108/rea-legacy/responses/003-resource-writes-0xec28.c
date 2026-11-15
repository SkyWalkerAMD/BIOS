
ulonglong FUN_0000ec28(undefined8 *param_1,short *param_2)

{
  byte *pbVar1;
  ulonglong uVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  int local_res18 [2];
  byte *local_res20;
  ulonglong local_38 [4];
  
  local_res20 = (byte *)0x0;
  local_38[2] = 0;
  local_res18[0] = 3;
  local_38[1] = 2;
  uVar2 = FUN_0001888c((longlong *)(local_38 + 1));
  if (-1 < (longlong)uVar2) {
    FUN_00018950(local_38 + 1,s_Accept_00019b70,s_application_json_charset_utf_8_00019b50);
    FUN_00018950(local_38 + 1,s_OData_Version_00019b80,&DAT_00019b78);
    uVar2 = FUN_00018af0(param_1,0,param_2,local_38 + 1,0,0,(ulonglong *)0x0,
                         (longlong *)&local_res20,local_38,local_res18);
    pbVar1 = local_res20;
    if (-1 < (longlong)uVar2) {
      if (local_res18[0] != 3) {
        uVar2 = 0x8000000000000018;
      }
      if (-1 < (longlong)uVar2) {
        if (local_res20 == (byte *)0x0) goto LAB_0000ed58;
        puVar3 = FUN_0001768c(local_res20);
        if (puVar3 == (undefined8 *)0x0) {
          uVar2 = 0x8000000000000001;
        }
        else {
          puVar4 = FUN_000186b4((longlong)puVar3,s_Members_0001ac40);
          uVar2 = FUN_0000eb5c(param_1,(longlong)puVar4);
          FUN_00016bcc(puVar3);
        }
      }
    }
    if (pbVar1 != (byte *)0x0) {
      (**(code **)(DAT_0001e070 + 0x48))(pbVar1);
    }
  }
LAB_0000ed58:
  if (local_38[2] != 0) {
    FUN_000188d4(local_38 + 1);
  }
  return uVar2;
}

