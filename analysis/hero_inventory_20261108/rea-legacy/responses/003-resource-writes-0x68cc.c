
ulonglong FUN_000068cc(undefined8 *param_1,longlong param_2)

{
  ulonglong uVar1;
  short *local_res10;
  short *local_res18;
  
  local_res18 = (short *)0x0;
  local_res10 = (short *)0x0;
  uVar1 = (**(code **)(param_2 + 8))(param_2,s_MemoryDomains_0001aca8,&local_res10);
  if ((-1 < (longlong)uVar1) && (local_res10 != (short *)0x0)) {
    uVar1 = FUN_00019114(param_1,local_res10);
    if ((longlong)uVar1 < 0) {
      uVar1 = FUN_00006774(param_1,local_res10);
    }
    (**(code **)(DAT_0001e070 + 0x48))(local_res10);
  }
  if ((uVar1 != 0x800000000000000b) && (1 < uVar1 + 0x7fffffffffffffee)) {
    uVar1 = (**(code **)(param_2 + 8))(param_2,s_Memory_0001a7e8,&local_res18);
    if ((-1 < (longlong)uVar1) && (local_res18 != (short *)0x0)) {
      uVar1 = FUN_00019114(param_1,local_res18);
      if ((longlong)uVar1 < 0) {
        uVar1 = FUN_00006364(param_1,local_res18);
      }
      (**(code **)(DAT_0001e070 + 0x48))(local_res18);
    }
  }
  return uVar1;
}

