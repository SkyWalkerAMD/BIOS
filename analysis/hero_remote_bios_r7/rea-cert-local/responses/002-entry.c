/* {"procedure": "0x3b4"} */

undefined8 entry(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  undefined8 local_res8;
  undefined1 local_res10 [24];
  
  DAT_00006348 = *(longlong *)(param_2 + 0x60);
  uVar3 = 0;
  DAT_00006350 = *(undefined8 *)(param_2 + 0x58);
  DAT_00006340 = param_2;
  local_res8 = param_1;
  FUN_00000340(1,(undefined4 *)0x0,(undefined4 *)0x0,(undefined4 *)&local_res8,(undefined4 *)0x0);
  if (DAT_00006358 == 0) {
    FUN_00002c74();
  }
  puVar2 = (undefined8 *)FUN_00001e6c(0x50);
  lVar1 = DAT_00006348;
  if (puVar2 == (undefined8 *)0x0) {
    uVar3 = 0x8000000000000009;
  }
  else {
    *puVar2 = 0x736c7472;
    (**(code **)(lVar1 + 0x50))(0x200,8,0x4d8,puVar2,&local_res8);
    (**(code **)(DAT_00006348 + 0xa8))(&DAT_00005b50,local_res8,local_res10);
    (**(code **)(DAT_00006348 + 0x68))(local_res8);
  }
  return uVar3;
}

