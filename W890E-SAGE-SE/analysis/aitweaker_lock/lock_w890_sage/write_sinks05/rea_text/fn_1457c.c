
undefined8 FUN_0001457c(undefined8 param_1,undefined8 param_2,undefined8 param_3,short param_4)

{
  undefined1 uVar1;
  undefined1 uVar2;
  longlong lVar3;
  ulonglong uVar4;
  longlong local_38 [2];
  undefined8 local_28;
  undefined4 local_20;
  undefined4 local_1c;
  undefined8 local_18 [2];
  
  local_38[0] = 0;
  local_18[0] = 0;
  if (DAT_00048190 != 0) {
    lVar3 = *(longlong *)(DAT_00048190 + 8);
    if (*(char *)(DAT_00048190 + 0x12) == '\f') {
      if (lVar3 != 0) {
        return 0;
      }
    }
    else {
      if (lVar3 == 0x1000) {
        return 0x8000000000000003;
      }
      if (lVar3 != 1) {
        return 0;
      }
    }
    DAT_00048180 = 0;
    DAT_00048280 = param_1;
    lVar3 = (**(code **)(DAT_000483d8 + 0x140))(&DAT_0002c5e8,0,&DAT_00048290);
    if (((-1 < lVar3) && (uVar4 = (*(code *)DAT_00048290[5])(), (uVar4 & 1) == 0)) &&
       ((uVar4 & 2) == 0)) {
      if (DAT_00048288 == 0) {
        DAT_00048288 = FUN_0001e280();
      }
      (*(code *)*DAT_00048290)(DAT_00048288);
      local_28 = 0x4bb5eba4ec87d643;
      local_20 = 0x3e3fe5a1;
      local_1c = 0xa90db236;
      (*(code *)DAT_00048290[4])(u_Setup_00041658,&local_28,local_38,local_18);
      lVar3 = DAT_00048288;
      *(undefined4 *)(DAT_00048288 + 0x18) = 0x5ad05ab;
      *(undefined4 *)(lVar3 + 0x1c) = 0x5ae05ac;
      if (param_4 == 0x2bfb) {
        FUN_000124bc();
        FUN_00012394(param_1);
        FUN_000125d0(param_1);
      }
      else if (param_4 == 0x2bfd) {
        uVar1 = *(undefined1 *)(local_38[0] + 0x156);
        uVar2 = *(undefined1 *)(local_38[0] + 0x155);
        FUN_00013dd8(param_1,uVar1);
        *(undefined1 *)(local_38[0] + 0x156) = uVar1;
        *(undefined1 *)(local_38[0] + 0x155) = uVar2;
        FUN_000124bc();
        FUN_00012394(param_1);
        local_28 = 0;
        (**(code **)(DAT_000483d8 + 0x80))(&local_28,&DAT_00030a68,0,0);
        (**(code **)(DAT_000483d8 + 0x90))(local_28,&DAT_00030a68,0);
      }
      else if (param_4 == 0x2bfe) {
        uVar1 = *(undefined1 *)(local_38[0] + 0x155);
        FUN_00013a54(uVar1);
        *(undefined1 *)(local_38[0] + 0x155) = uVar1;
        FUN_000124bc();
      }
    }
  }
  return 0;
}

