// 0x440

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong entry(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  
  FUN_00000510(param_1,param_2);
  if (DAT_00001fb8 == 0) {
    DAT_00001fa8 = *(undefined8 *)(param_2 + 0x60);
    _DAT_00001fb0 = *(undefined8 *)(param_2 + 0x58);
    DAT_00001fb8 = param_2;
  }
  _DAT_00001e70 = param_1;
  _DAT_00001e78 = param_1;
  lVar1 = (**(code **)(DAT_00001f90 + 0x148))
                    (&DAT_00001e78,&DAT_00001e20,&PTR_FUN_00001e50,&DAT_00001e30,&PTR_LAB_00001e98,
                     &DAT_00001dd0,&PTR_LAB_00001e80,0);
  if ((lVar1 < 0) && (DAT_00001fa0 != 0)) {
    (**(code **)(*(longlong *)(param_2 + 0x60) + 0x48))();
    DAT_00001fa0 = 0;
  }
  return lVar1;
}


// 0x7c0

longlong FUN_000007c0(undefined8 param_1,undefined8 param_2)

{
  longlong lVar1;
  undefined4 *puVar2;
  undefined8 local_res10;
  undefined8 local_res18 [2];
  
  local_res18[0] = 0;
  local_res10 = param_2;
  lVar1 = (**(code **)(DAT_00001f90 + 0x118))(param_2,0x1e00,local_res18,param_1,param_2,0x10);
  if (lVar1 < 0) {
    lVar1 = -0x7ffffffffffffffd;
  }
  else {
    puVar2 = (undefined4 *)FUN_00001610(0xe8);
    if (puVar2 == (undefined4 *)0x0) {
      lVar1 = -0x7ffffffffffffff7;
    }
    else {
      *puVar2 = 0x4e535255;
      *(undefined8 *)(puVar2 + 6) = param_1;
      *(undefined8 *)(puVar2 + 8) = local_res10;
      *(undefined8 *)(puVar2 + 10) = 0xa0c;
      lVar1 = DAT_00001f90;
      *(undefined8 *)(puVar2 + 0xc) = 0xa00;
      lVar1 = (**(code **)(lVar1 + 0x148))
                        (&local_res10,&DAT_00001e40,puVar2,&DAT_00001dc0,puVar2 + 10,0);
      if (lVar1 < 0) {
        (**(code **)(DAT_00001f90 + 0x48))(puVar2);
      }
    }
  }
  return lVar1;
}

