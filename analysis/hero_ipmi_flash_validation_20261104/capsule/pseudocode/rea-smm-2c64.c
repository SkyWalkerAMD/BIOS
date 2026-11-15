
ulonglong FUN_00002c64(longlong param_1,longlong param_2)

{
  uint uVar1;
  int iVar2;
  ulonglong uVar3;
  longlong *plVar4;
  uint uVar5;
  longlong lVar6;
  uint *puVar7;
  
  iVar2 = DAT_00005240;
  lVar6 = (ulonglong)*(ushort *)(param_1 + 0x1e) + param_1;
  uVar5 = *(uint *)(lVar6 + 0xc);
  if (uVar5 != 0) {
    puVar7 = (uint *)(lVar6 + 8);
    do {
      if ((puVar7[3] >> 9 & 1) != 0 && (puVar7[3] & 10) != 0) {
        uVar1 = *puVar7;
        for (plVar4 = (longlong *)((ulonglong)uVar1 + param_2);
            ((plVar4 != (longlong *)0x0 && (0x57 < uVar5)) &&
            (plVar4 <= (longlong *)
                       ((longlong)((ulonglong)uVar1 + param_2) + ((ulonglong)uVar5 - 0x57))));
            plVar4 = (longlong *)((longlong)plVar4 + 1)) {
          if ((((int)*plVar4 == iVar2) &&
              (lVar6 = FUN_00004650((longlong *)&DAT_00005240,plVar4,0x10), lVar6 == 0)) &&
             ((int)plVar4[2] == 0x44494624)) {
            uVar3 = FUN_00002b34((longlong)(plVar4 + 2));
            return uVar3;
          }
        }
      }
      uVar5 = puVar7[7];
      puVar7 = puVar7 + 6;
    } while (uVar5 != 0);
  }
  return 0x8000000000000019;
}

