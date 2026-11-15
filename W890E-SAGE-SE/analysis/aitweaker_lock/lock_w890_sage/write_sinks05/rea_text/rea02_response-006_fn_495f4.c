
ulonglong WS05_495f4(longlong param_1)

{
  byte bVar1;
  ulonglong uVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  longlong lVar5;
  undefined8 uVar6;
  longlong *plVar7;
  ulonglong uVar8;
  uint *puVar9;
  undefined8 local_res10;
  
  local_res10 = 0;
  uVar2 = (**(code **)(DAT_000afbc8 + 0x140))(&DAT_00093628,0);
  if (((uVar2 == 0) && (DAT_000afe28 != 0)) && (uVar8 = 0, *(int *)(param_1 + 0x1c) != 0)) {
    puVar9 = (uint *)(param_1 + 0x20);
    do {
      plVar7 = (longlong *)((ulonglong)*puVar9 + DAT_000bab08);
      if ((*(short *)((longlong)plVar7 + 0x14) == 9) &&
         (uVar2 = FUN_00049e60(param_1,uVar8), (char)uVar2 == '\0')) {
        bVar1 = FUN_00049128((longlong)plVar7);
        if ((bVar1 == 6) && ((*(uint *)((longlong)plVar7 + 0x1c) & 0x40) == 0)) {
          *(uint *)((longlong)plVar7 + 0x1c) = *(uint *)((longlong)plVar7 + 0x1c) | 0x40;
          puVar3 = FUN_0004bc70(DAT_000babe8,0x4a,(short *)0x0);
          lVar5 = plVar7[6];
          if (*(short *)(lVar5 + 2) == -1) {
            puVar4 = (undefined8 *)0x0;
          }
          else {
            puVar4 = FUN_0004bc70(*plVar7,*(short *)(lVar5 + 2),(short *)0x0);
            lVar5 = plVar7[6];
          }
          (**(code **)(DAT_000afe28 + 0x58))(puVar3,puVar4,*(undefined1 *)(lVar5 + 4),&local_res10);
          if (puVar3 != (undefined8 *)0x0) {
            (**(code **)(DAT_000afbc8 + 0x48))(puVar3);
          }
          if (puVar4 != (undefined8 *)0x0) {
            (**(code **)(DAT_000afbc8 + 0x48))(puVar4);
          }
        }
        else {
          bVar1 = FUN_00049128((longlong)plVar7);
          if ((bVar1 != 6) && ((*(uint *)((longlong)plVar7 + 0x1c) & 0x40) != 0)) {
            *(uint *)((longlong)plVar7 + 0x1c) = *(uint *)((longlong)plVar7 + 0x1c) & 0xffffffbf;
          }
        }
        bVar1 = FUN_00049128((longlong)plVar7);
        if (bVar1 == 4) {
          puVar3 = FUN_0004bc70(DAT_000babe8,0x4e,(short *)0x0);
          if (*(short *)(plVar7[6] + 2) == -1) {
            puVar4 = (undefined8 *)0x0;
          }
          else {
            puVar4 = FUN_0004bc70(*plVar7,*(short *)(plVar7[6] + 2),(short *)0x0);
          }
          uVar6 = (**(code **)(DAT_000afe28 + 0x20))(puVar3,puVar4,1,0);
          if (puVar3 != (undefined8 *)0x0) {
            uVar6 = (**(code **)(DAT_000afbc8 + 0x48))(puVar3);
          }
          if (puVar4 != (undefined8 *)0x0) {
            uVar6 = (**(code **)(DAT_000afbc8 + 0x48))(puVar4);
          }
          return CONCAT71((int7)((ulonglong)uVar6 >> 8),1);
        }
      }
      uVar2 = (ulonglong)*(uint *)(param_1 + 0x1c);
      uVar8 = uVar8 + 1;
      puVar9 = puVar9 + 1;
    } while (uVar8 < uVar2);
  }
  return uVar2 & 0xffffffffffffff00;
}

