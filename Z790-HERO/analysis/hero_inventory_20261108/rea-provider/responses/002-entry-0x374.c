
undefined8
FUN_00000374(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 **param_4)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  code *pcVar3;
  undefined8 local_res8;
  undefined8 local_res10 [3];
  
  local_res8 = 0;
  pcVar3 = (code *)0x348;
  local_res10[0] = CONCAT62((int6)((ulonglong)param_2 >> 0x10),0x61);
  puVar1 = FUN_00013570(0,0x348);
  if (puVar1 == (undefined8 *)0x0) {
    uVar2 = 0x8000000000000009;
  }
  else {
    *(undefined4 *)puVar1 = 0x4d494853;
    *(undefined4 *)((longlong)puVar1 + 4) = 0x348;
    *(undefined2 *)(puVar1 + 1) = 0x801;
    if ((undefined8 *)((longlong)puVar1 + 10) != local_res10) {
      param_3 = 2;
      pcVar3 = (code *)local_res10;
      FUN_00000280((undefined8 *)((longlong)puVar1 + 10),(undefined8 *)pcVar3,2);
    }
    FUN_00015514(&DAT_000162d0,pcVar3,param_3,param_4);
    FUN_00015514(&DAT_00016280,pcVar3,param_3,param_4);
    uVar2 = (**(code **)(DAT_00018a28 + 0x148))(&local_res8,&DAT_00016470,puVar1,0);
  }
  return uVar2;
}

