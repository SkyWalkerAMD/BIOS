
ulonglong Candidate_ACE_SaveValidation(void)

{
  byte bVar1;
  undefined8 *in_RAX;
  ulonglong uVar2;
  longlong lVar3;
  undefined8 *puVar4;
  undefined8 uVar5;
  uint *puVar6;
  undefined8 *puVar7;
  int iVar8;
  uint uVar9;
  longlong *plVar10;
  longlong *plVar11;
  uint *puVar12;
  undefined8 *local_res8;
  undefined8 *local_res10;
  
  puVar4 = (undefined8 *)0x0;
  puVar6 = DAT_00092270;
  puVar7 = puVar4;
  if (*DAT_00092270 != 0) {
    do {
      in_RAX = puVar7;
      iVar8 = (int)in_RAX;
      plVar10 = (longlong *)((ulonglong)puVar6[(longlong)in_RAX + 1] + (longlong)puVar6);
      if ((*plVar10 != 0) && (*(int *)((longlong)plVar10 + 0x1c) != 0)) {
        puVar12 = (uint *)(plVar10 + 4);
        puVar7 = puVar4;
        do {
          plVar11 = (longlong *)((ulonglong)*puVar12 + DAT_00092288);
          if ((((*(short *)((longlong)plVar11 + 0x14) == 0x16) &&
               (uVar2 = FUN_00032adc((longlong)plVar10,(ulonglong)puVar7), (char)uVar2 == '\0')) &&
              (bVar1 = FUN_00031df4((longlong)plVar11), bVar1 == 5)) &&
             ((lVar3 = (**(code **)(DAT_000824c8 + 0x140))(&DAT_0006a780,0), lVar3 == 0 &&
              (DAT_000827a0 != 0)))) {
            puVar7 = FUN_00033df4(DAT_00092b30,0x4e,(short *)0x0);
            local_res8 = puVar7;
            if (*(short *)(plVar11[6] + 2) != -1) {
              puVar4 = FUN_00033df4(*plVar11,*(short *)(plVar11[6] + 2),(short *)0x0);
            }
            local_res10 = puVar4;
            (**(code **)(DAT_000827a0 + 0x20))(puVar7,puVar4,1,0);
            FUN_00005958((longlong *)&local_res8);
            uVar5 = FUN_00005958((longlong *)&local_res10);
            return CONCAT71((int7)((ulonglong)uVar5 >> 8),1);
          }
          in_RAX = (undefined8 *)(ulonglong)*(uint *)((longlong)plVar10 + 0x1c);
          puVar7 = (undefined8 *)((longlong)puVar7 + 1);
          puVar12 = puVar12 + 1;
          puVar6 = DAT_00092270;
        } while (puVar7 < in_RAX);
      }
      uVar9 = iVar8 + 1;
      puVar7 = (undefined8 *)(ulonglong)uVar9;
    } while (uVar9 < *puVar6);
  }
  return (ulonglong)in_RAX & 0xffffffffffffff00;
}

