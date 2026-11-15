
undefined8 FUN_0000220c(longlong param_1)

{
  undefined8 *puVar1;
  ushort uVar2;
  short sVar3;
  longlong *plVar4;
  longlong lVar5;
  undefined8 uVar6;
  short *psVar7;
  ulonglong uVar8;
  longlong *plVar9;
  undefined1 local_res10 [8];
  ulonglong local_res18;
  longlong *local_res20;
  ulonglong local_48;
  longlong local_40;
  longlong local_38;
  longlong local_30;
  
  local_40 = 0;
  local_res20 = (longlong *)0x0;
  local_res18 = 0;
  lVar5 = (**(code **)(DAT_00005818 + 0x138))(2,&DAT_000050a0,0,&local_48,&local_38);
  if ((-1 < lVar5) && (local_48 != 0)) {
    uVar8 = 0;
    if (local_48 != 0) {
      do {
        lVar5 = (**(code **)(DAT_00005818 + 0x98))
                          (*(undefined8 *)(local_38 + uVar8 * 8),&DAT_000050a0,&local_30);
        if (((-1 < lVar5) &&
            (lVar5 = (**(code **)(local_30 + 0x18))
                               (local_30,&DAT_000051c8,0x18,0,&local_res20,&local_res18,local_res10)
            , lVar5 == 0)) &&
           (lVar5 = FUN_00004650((longlong *)&DAT_00005230,local_res20,0x10), lVar5 == 0)) break;
        uVar8 = uVar8 + 1;
      } while (uVar8 < local_48);
    }
    (**(code **)(DAT_00005818 + 0x48))(local_38);
    plVar4 = local_res20;
    if (uVar8 < local_48) {
      plVar9 = local_res20 + 2;
      lVar5 = FUN_00004650(plVar9,(longlong *)&DAT_000050b0,0x10);
      if ((lVar5 == 0) && (uVar6 = FUN_00002d30((longlong)plVar9), (char)uVar6 != '\0')) {
        uVar2 = *(ushort *)((longlong)plVar4 + 0x2e);
        local_res18 = (ulonglong)(int)((uint)*(ushort *)((longlong)plVar4 + 0x2c) - (uint)uVar2);
        puVar1 = (undefined8 *)((longlong)plVar9 + (ulonglong)uVar2);
        FUN_0000216c(&local_40,puVar1,local_res18);
        if ((puVar1 != (undefined8 *)0x0) && (local_res18 != 0)) goto LAB_000023ca;
      }
    }
  }
  psVar7 = (short *)FUN_0000442c(param_1,(longlong *)&DAT_000051b8);
  if (psVar7 != (short *)0x0) {
    do {
      sVar3 = *psVar7;
      while( true ) {
        if (sVar3 == -1) goto LAB_000023ca;
        psVar7 = (short *)((longlong)psVar7 + (ulonglong)(ushort)psVar7[1]);
        if (*psVar7 == 4) break;
        sVar3 = *psVar7;
      }
      lVar5 = FUN_00004650((longlong *)(psVar7 + 4),(longlong *)&DAT_000051a8,0x10);
    } while (lVar5 != 0);
    local_res18 = (ulonglong)(ushort)psVar7[1] - 0x18;
    FUN_0000216c(&local_40,(undefined8 *)(psVar7 + 0xc),local_res18);
  }
LAB_000023ca:
  if (local_res20 != (longlong *)0x0) {
    (**(code **)(DAT_00005818 + 0x48))();
  }
  if (local_res18 < 0x18) {
    uVar6 = 0x800000000000000e;
  }
  else {
    DAT_000057a0 = local_40;
    uVar6 = 0;
  }
  return uVar6;
}

