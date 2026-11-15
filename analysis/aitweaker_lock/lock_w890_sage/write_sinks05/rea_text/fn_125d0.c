
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_000125d0(undefined8 param_1,undefined8 param_2)

{
  longlong lVar1;
  byte bVar2;
  undefined2 uVar4;
  undefined8 local_res10;
  undefined8 local_res18 [2];
  undefined8 local_288;
  undefined8 uStack_280;
  undefined8 local_278;
  undefined4 local_270;
  undefined2 local_26c;
  undefined8 local_268;
  undefined8 uStack_260;
  undefined8 local_258;
  undefined4 local_250;
  undefined4 local_248;
  undefined4 uStack_244;
  undefined4 uStack_240;
  undefined4 uStack_23c;
  undefined2 local_238;
  undefined1 local_228 [512];
  uint uVar3;
  
  local_res10 = param_2;
  FUN_00001280(local_228,0,0x200);
  local_258 = 0;
  local_268 = 0;
  uStack_260 = 0;
  local_250 = 0;
  uVar3 = 0x2f;
  local_288 = 0;
  uStack_280 = 0;
  local_278 = 0;
  local_270 = 0;
  local_26c = 0;
  local_238 = DAT_00042a20;
  local_248 = _DAT_00042a10;
  uStack_244 = uRam0000000000042a14;
  uStack_240 = uRam0000000000042a18;
  uStack_23c = uRam0000000000042a1c;
  uVar4 = (undefined2)local_res10;
  do {
    FUN_0001e3ac(&local_268,0x1c,u_ProfileName_d_000429d0,uVar3 - 0x2e);
    local_res10 = 0x1c;
    lVar1 = (**(code **)(DAT_000483e8 + 0x48))(&local_268,&DAT_00030030,0,&local_res10,&local_288);
    if (lVar1 < 0) {
      local_res18[0] = 0x200;
      FUN_00022800(param_1,0x592,local_res18,local_228);
    }
    else {
      FUN_0001e3ac(local_228,0x200,u__s_s_00042a28,&local_248,&local_288);
    }
    if (uVar3 == 0x2f) {
      uVar4 = 0x593;
    }
    else if (uVar3 == 0x30) {
      uVar4 = 0x594;
    }
    else if (uVar3 == 0x31) {
      uVar4 = 0x595;
    }
    else if (uVar3 == 0x32) {
      uVar4 = 0x596;
    }
    else if (uVar3 == 0x33) {
      uVar4 = 0x597;
    }
    else if (uVar3 == 0x34) {
      uVar4 = 0x598;
    }
    else if (uVar3 == 0x35) {
      uVar4 = 0x599;
    }
    else if (uVar3 == 0x36) {
      uVar4 = 0x59a;
    }
    FUN_00001954(param_1,uVar4,local_228);
    bVar2 = (char)uVar3 + 1;
    uVar3 = (uint)bVar2;
  } while (bVar2 < 0x37);
  return;
}

