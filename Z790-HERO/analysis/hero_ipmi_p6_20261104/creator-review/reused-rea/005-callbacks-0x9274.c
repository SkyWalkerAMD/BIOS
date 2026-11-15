
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong FUN_00009274(longlong param_1,longlong param_2,undefined8 param_3,undefined **param_4,
                     undefined8 *param_5,undefined8 *param_6)

{
  longlong *plVar1;
  longlong lVar2;
  undefined8 *puVar3;
  undefined **ppuVar4;
  undefined **ppuVar5;
  undefined **ppuVar6;
  undefined8 local_res18;
  undefined **local_res20;
  
  ppuVar6 = (undefined **)0x0;
  local_res18 = 0;
  ppuVar4 = &PTR_DAT_0000a660;
  ppuVar5 = ppuVar6;
  local_res20 = param_4;
  do {
    if ((longlong *)*ppuVar4 != (longlong *)0x0) {
      lVar2 = FUN_00009614((longlong *)(param_2 + 2),(longlong *)*ppuVar4,0x10);
      if (lVar2 == 0) break;
    }
    ppuVar5 = (undefined **)((longlong)ppuVar5 + 1);
    ppuVar4 = ppuVar4 + 4;
  } while (ppuVar5 == (undefined **)0x0);
  if (ppuVar5 == (undefined **)(IMAGE_DOS_HEADER_00000000.e_magic + 1)) {
    ppuVar4 = (undefined **)&DAT_0000d278;
  }
  else {
    ppuVar4 = &PTR_DAT_0000a660 + (longlong)ppuVar5 * 4;
    plVar1 = (longlong *)(&PTR_DAT_0000a668)[(longlong)ppuVar5 * 4];
    if (plVar1 == (longlong *)0x0) {
      (&PTR_DAT_0000a668)[(longlong)ppuVar5 * 4] = (undefined *)&PTR_LAB_0000d218;
    }
    else {
      if (*plVar1 == 0) {
        *plVar1 = (longlong)&LAB_00008c8c;
      }
      if (*(longlong *)((&PTR_DAT_0000a668)[(longlong)ppuVar5 * 4] + 8) == 0) {
        *(undefined1 **)((&PTR_DAT_0000a668)[(longlong)ppuVar5 * 4] + 8) = &LAB_0000900c;
      }
      if (*(longlong *)((&PTR_DAT_0000a668)[(longlong)ppuVar5 * 4] + 0x10) == 0) {
        *(undefined1 **)((&PTR_DAT_0000a668)[(longlong)ppuVar5 * 4] + 0x10) = &LAB_00009268;
      }
    }
  }
  lVar2 = (**(code **)(DAT_000154a0 + 0x98))
                    (*(undefined8 *)(param_1 + 0x18),&DAT_0000d1f8,&local_res20);
  if (lVar2 < 0) {
    local_res20 = ppuVar6;
  }
  local_res20 = (undefined **)FUN_00007e80((char *)local_res20,*(undefined8 **)(param_1 + 0x20));
  _DAT_0000d234 = *(undefined8 *)(param_2 + 2);
  uRam000000000000d23c = *(undefined8 *)(param_2 + 10);
  puVar3 = FUN_00007e80((char *)local_res20,(undefined8 *)&DAT_0000d230);
  (**(code **)(DAT_000154a0 + 0x48))(local_res20);
  lVar2 = (**(code **)(DAT_000154a0 + 0x148))
                    (&local_res18,&DAT_0000d1f8,puVar3,&DAT_0000d258,ppuVar4[1],0);
  if (-1 < lVar2) {
    if (param_6 != (undefined8 *)0x0) {
      *param_6 = local_res18;
    }
    if (param_5 != (undefined8 *)0x0) {
      if (ppuVar4 == (undefined **)&DAT_0000d278) {
        ppuVar4 = ppuVar6;
      }
      *param_5 = ppuVar4;
    }
    lVar2 = 0;
  }
  return lVar2;
}

