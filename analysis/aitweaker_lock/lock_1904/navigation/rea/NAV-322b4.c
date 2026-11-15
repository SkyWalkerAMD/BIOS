
ulonglong Candidate_PageLeaveVeto(longlong param_1)

{
  byte bVar1;
  undefined8 *puVar2;
  ulonglong uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  undefined8 uVar6;
  longlong *plVar7;
  undefined8 *puVar8;
  uint *puVar9;
  undefined8 *local_res10;
  undefined8 *local_res18;
  undefined8 local_res20;
  
  puVar5 = (undefined8 *)0x0;
  local_res20 = 0;
  puVar2 = (undefined8 *)(**(code **)(DAT_000824c8 + 0x140))(&DAT_0006a780,0);
  if (((puVar2 == (undefined8 *)0x0) && (DAT_000827a0 != 0)) && (*(int *)(param_1 + 0x1c) != 0)) {
    puVar9 = (uint *)(param_1 + 0x20);
    puVar8 = puVar5;
    do {
      plVar7 = (longlong *)((ulonglong)*puVar9 + DAT_00092288);
      if ((*(short *)((longlong)plVar7 + 0x14) == 9) &&
         (uVar3 = FUN_00032adc(param_1,(ulonglong)puVar8), (char)uVar3 == '\0')) {
        bVar1 = FUN_00031df4((longlong)plVar7);
        if ((bVar1 == 6) && ((*(uint *)((longlong)plVar7 + 0x1c) & 0x40) == 0)) {
          *(uint *)((longlong)plVar7 + 0x1c) = *(uint *)((longlong)plVar7 + 0x1c) | 0x40;
          puVar4 = FUN_00033df4(DAT_00092b30,0x49,(short *)0x0);
          puVar2 = puVar5;
          local_res10 = puVar4;
          if (*(short *)(plVar7[6] + 2) != -1) {
            puVar2 = FUN_00033df4(*plVar7,*(short *)(plVar7[6] + 2),(short *)0x0);
          }
          local_res18 = puVar2;
          (**(code **)(DAT_000827a0 + 0x58))
                    (puVar4,puVar2,*(undefined1 *)(plVar7[6] + 4),&local_res20);
          FUN_00005958((longlong *)&local_res10);
          FUN_00005958((longlong *)&local_res18);
        }
        else {
          bVar1 = FUN_00031df4((longlong)plVar7);
          if ((bVar1 != 6) && ((*(uint *)((longlong)plVar7 + 0x1c) & 0x40) != 0)) {
            *(uint *)((longlong)plVar7 + 0x1c) = *(uint *)((longlong)plVar7 + 0x1c) & 0xffffffbf;
          }
        }
        bVar1 = FUN_00031df4((longlong)plVar7);
        if (bVar1 == 4) {
          puVar2 = FUN_00033df4(DAT_00092b30,0x4d,(short *)0x0);
          local_res10 = puVar2;
          if (*(short *)(plVar7[6] + 2) != -1) {
            puVar5 = FUN_00033df4(*plVar7,*(short *)(plVar7[6] + 2),(short *)0x0);
          }
          local_res18 = puVar5;
          (**(code **)(DAT_000827a0 + 0x20))(puVar2,puVar5,1,0);
          FUN_00005958((longlong *)&local_res10);
          uVar6 = FUN_00005958((longlong *)&local_res18);
          return CONCAT71((int7)((ulonglong)uVar6 >> 8),1);
        }
      }
      puVar2 = (undefined8 *)(ulonglong)*(uint *)(param_1 + 0x1c);
      puVar8 = (undefined8 *)((longlong)puVar8 + 1);
      puVar9 = puVar9 + 1;
    } while (puVar8 < puVar2);
  }
  return (ulonglong)puVar2 & 0xffffffffffffff00;
}

