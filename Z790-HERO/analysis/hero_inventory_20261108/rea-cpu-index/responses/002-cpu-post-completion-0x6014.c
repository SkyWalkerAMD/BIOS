
byte * FUN_00006014(undefined8 *param_1,longlong param_2,longlong param_3,longlong param_4)

{
  longlong lVar1;
  byte *pbVar2;
  longlong *plVar3;
  longlong lVar4;
  longlong lVar5;
  longlong lVar6;
  short *local_res10;
  short *local_48;
  longlong local_40;
  longlong local_38;
  longlong local_30;
  
  local_40 = 0;
  local_48 = (short *)0x0;
  local_res10 = (short *)0x0;
  pbVar2 = (byte *)(**(code **)(param_2 + 8))(param_2,0,&local_40);
  lVar6 = 0;
  if ((-1 < (longlong)pbVar2) &&
     (pbVar2 = (byte *)(**(code **)(param_2 + 8))(param_2,s_Memory_0001a7e8,&local_48),
     -1 < (longlong)pbVar2)) {
    (**(code **)(param_2 + 8))(param_2,s_MemoryDomains_0001aca8,&local_res10);
    lVar6 = *(longlong *)(param_3 + 0x330);
    lVar4 = 0;
    if (lVar6 != 0) {
      plVar3 = *(longlong **)(param_3 + 0x338);
      lVar5 = lVar4;
      do {
        lVar1 = *plVar3;
        plVar3 = plVar3 + 1;
        lVar4 = lVar5 + 1;
        if (*(char *)(lVar1 + 0x18) != '\x02') {
          lVar4 = lVar5;
        }
        lVar6 = lVar6 + -1;
        lVar5 = lVar4;
      } while (lVar6 != 0);
    }
    local_38 = FUN_00015ad4(lVar4 * 0x48);
    if (local_38 == 0) {
      pbVar2 = (byte *)0x8000000000000009;
      lVar6 = local_38;
    }
    else {
      local_30 = lVar4;
      pbVar2 = (byte *)FUN_00005e7c(param_1,param_3,local_48,param_4,&local_38);
      lVar6 = local_38;
      if ((-1 < (longlong)pbVar2) && (local_res10 != (short *)0x0)) {
        pbVar2 = FUN_00005ba8(param_1,param_3,local_res10,&local_38);
        lVar6 = local_38;
      }
    }
  }
  if (local_40 != 0) {
    (**(code **)(DAT_0001e070 + 0x48))();
  }
  if (local_res10 != (short *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))();
  }
  if (local_48 != (short *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))();
  }
  if (lVar6 != 0) {
    if (local_30 != 0) {
      plVar3 = (longlong *)(lVar6 + 8);
      lVar4 = local_30;
      do {
        if (*plVar3 != 0) {
          (**(code **)(DAT_0001e070 + 0x48))();
        }
        plVar3 = plVar3 + 9;
        lVar4 = lVar4 + -1;
      } while (lVar4 != 0);
    }
    (**(code **)(DAT_0001e070 + 0x48))(lVar6);
  }
  return pbVar2;
}

