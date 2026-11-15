
undefined8 FUN_0000062c(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  undefined8 uVar2;
  undefined4 local_res8 [4];
  undefined8 local_res18;
  undefined8 local_res20;
  undefined1 local_38 [8];
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  uVar2 = 0;
  if (DAT_000154b0 == 0) {
    DAT_000154a0 = *(longlong *)(param_2 + 0x60);
    DAT_000154a8 = *(undefined8 *)(param_2 + 0x58);
    DAT_000154b0 = param_2;
  }
  local_res18 = 0x267;
  DAT_00015400 = param_1;
  lVar1 = (**(code **)(DAT_00015460 + 0x48))
                    (u_ServerSetup_0000d2c0,&DAT_0000a390,local_res8,&local_res18,&DAT_00015b20);
  if (lVar1 == -0x7ffffffffffffff2) {
    FUN_00000890((undefined *)0x0,0,(undefined8 *)0x800000000000000e);
    lVar1 = (**(code **)(DAT_00015460 + 0x58))
                      (u_ServerSetup_0000d2c0,&DAT_0000a390,local_res8[0],0x267,&DAT_00015b20);
    if (lVar1 < 0) {
      uVar2 = 0x8000000000000003;
    }
  }
  else {
    local_30 = 0xdbc9fd21;
    local_2c = 0x45b0fad8;
    local_28 = 0x1527789e;
    local_24 = 0x93cc6788;
    lVar1 = (**(code **)(DAT_000154a0 + 0x50))(0x200,8,0x890,0,&local_res20);
    if (-1 < lVar1) {
      (**(code **)(DAT_000154a0 + 0xa8))(&local_30,local_res20,local_38);
    }
  }
  return uVar2;
}

