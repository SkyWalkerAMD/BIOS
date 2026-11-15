/* {"status": "resolved", "address": "0x580", "name": "FUN_00000580"} */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong FUN_00000580(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  longlong lVar2;
  ulonglong uVar3;
  undefined *puVar4;
  undefined4 local_res18 [2];
  longlong local_res20;
  undefined8 local_38;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  local_res20 = 0;
  local_res18[0] = 0;
  local_30 = 0xec87d643;
  local_2c = 0x4bb5eba4;
  local_28 = 0x3e3fe5a1;
  local_24 = 0xa90db236;
  lVar2 = FUN_00001d44(param_1,&local_30,local_res18,&local_38,&local_res20);
  lVar1 = local_res20;
  if ((lVar2 < 0) || (*(char *)(local_res20 + 0xbf5) != '\0')) {
    if (DAT_00007b58 == 0) {
      _DAT_00007b50 = *(undefined8 *)(param_2 + 0x58);
      DAT_00007b58 = param_2;
    }
    uVar3 = FUN_00005634();
    if ((int)uVar3 != 0x20) {
      uVar3 = FUN_00005634();
      if ((int)uVar3 != 0x12) {
        puVar4 = &DAT_00007178;
        _DAT_00007170 = param_1;
        lVar2 = (**(code **)(DAT_00007b28 + 0x148))(&DAT_00007178,&DAT_00007140,&PTR_FUN_00007150,0)
        ;
        if (-1 < lVar2) {
          FUN_00000688(puVar4);
        }
      }
    }
  }
  if (lVar1 != 0) {
    (**(code **)(DAT_00007b28 + 0x48))(lVar1);
  }
  return lVar2;
}



/* {"status": "resolved", "address": "0x688", "name": "FUN_00000688"} */

longlong FUN_00000688(undefined8 param_1)

{
  longlong lVar1;
  longlong lVar2;
  undefined4 local_res8 [2];
  longlong local_res10;
  undefined8 local_res18 [2];
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  local_res10 = 0;
  local_res8[0] = 0;
  local_28 = 0xec87d643;
  local_24 = 0x4bb5eba4;
  local_20 = 0x3e3fe5a1;
  local_1c = 0xa90db236;
  lVar2 = FUN_00001d44(param_1,&local_28,local_res8,local_res18,&local_res10);
  lVar1 = local_res10;
  if (-1 < lVar2) {
    if (*(short *)(local_res10 + 0xc77) == -1) {
      if ((wchar_t *)(local_res10 + 0xc37) != u_169_254_0_17_00007200) {
        FUN_000002a0((undefined8 *)(local_res10 + 0xc37),(undefined8 *)u_169_254_0_17_00007200,0x1a)
        ;
      }
      if ((wchar_t *)(lVar1 + 0xc57) != u_255_255_0_0_00007220) {
        FUN_000002a0((undefined8 *)(lVar1 + 0xc57),(undefined8 *)u_255_255_0_0_00007220,0x18);
      }
      *(undefined2 *)(lVar1 + 0xc77) = 0x1bb;
      lVar2 = (**(code **)(DAT_00007b38 + 0x58))
                        (u_Setup_000071f0,&local_28,local_res8[0],local_res18[0],lVar1);
    }
    (**(code **)(DAT_00007b28 + 0x48))(lVar1);
  }
  return lVar2;
}

