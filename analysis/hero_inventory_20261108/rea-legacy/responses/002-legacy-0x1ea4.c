
ulonglong FUN_00001ea4(undefined8 *param_1,longlong param_2,longlong param_3)

{
  longlong lVar1;
  ulonglong uVar2;
  undefined1 *puVar3;
  short *local_res10;
  short *local_res20;
  
  local_res20 = (short *)0x0;
  local_res10 = (short *)0x0;
  lVar1 = (**(code **)(param_2 + 0x10))(param_2,s_Assembly_0001a110,&local_res10);
  if ((((lVar1 < 0) ||
       (uVar2 = FUN_00003f3c((byte *)(param_3 + 0x1d0),param_1,local_res10), (longlong)uVar2 < 0))
      && (uVar2 = (**(code **)(param_2 + 0x10))(param_2,s_PCIeSlots_0001a0a8,&local_res20),
         -1 < (longlong)uVar2)) && (puVar3 = FUN_00016b80(), puVar3 != (undefined1 *)0x0)) {
    *(undefined4 *)(puVar3 + 0x18) = 6;
    uVar2 = FUN_00001814(param_3,(byte *)(param_3 + 0x2a8),(longlong)puVar3);
    if (-1 < (longlong)uVar2) {
      uVar2 = FUN_00003eb4(param_1,(longlong)puVar3,local_res20);
    }
  }
  return uVar2;
}

