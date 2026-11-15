
longlong WS05_8efc8(ushort *param_1)

{
  ushort uVar1;
  ushort *puVar2;
  undefined8 in_RAX;
  longlong lVar3;
  undefined8 *puVar4;
  undefined8 uVar5;
  short *psVar6;
  ushort *puVar7;
  longlong lVar8;
  undefined8 *puVar9;
  undefined8 *puVar10;
  
  lVar3 = 0;
  if (param_1 == (ushort *)0x0) {
    lVar3 = CONCAT71((int7)((ulonglong)in_RAX >> 8),1);
  }
  else {
    puVar4 = DAT_000b8c28;
    if (DAT_000b8c28 == (undefined8 *)0x0) {
      puVar7 = param_1;
      DAT_000b8c28 = FUN_00059b50(param_1,0x18);
      uVar5 = 0;
      if (DAT_000b8c28 != (undefined8 *)0x0) {
        DAT_000b8c28[2] = 0;
        uVar1 = *param_1;
        puVar2 = param_1;
        lVar8 = lVar3;
        while (uVar1 != 0) {
          puVar2 = puVar2 + 1;
          lVar8 = lVar8 + 1;
          uVar1 = *puVar2;
        }
        puVar4 = FUN_00059b50(puVar7,lVar8 * 2 + 2);
        *DAT_000b8c28 = puVar4;
        uVar1 = *param_1;
        puVar7 = param_1;
        lVar8 = lVar3;
        while (uVar1 != 0) {
          puVar7 = puVar7 + 1;
          lVar8 = lVar8 + 1;
          uVar1 = *puVar7;
        }
        uVar5 = FUN_00059244((short *)*DAT_000b8c28,lVar8 + 1,(short *)param_1);
      }
    }
    else {
      do {
        puVar9 = puVar4;
        puVar7 = (ushort *)*puVar9;
        puVar10 = puVar9;
        lVar8 = FUN_00059000(puVar7,param_1);
        if (lVar8 == 0) {
          lVar3 = 1;
          uVar5 = 0;
          goto LAB_0008f108;
        }
        puVar4 = (undefined8 *)puVar10[2];
      } while ((undefined8 *)puVar10[2] != (undefined8 *)0x0);
      puVar4 = FUN_00059b50(puVar7,0x18);
      uVar5 = 0;
      if (puVar4 != (undefined8 *)0x0) {
        puVar4[2] = 0;
        uVar1 = *param_1;
        puVar2 = param_1;
        lVar8 = lVar3;
        while (uVar1 != 0) {
          puVar2 = puVar2 + 1;
          lVar8 = lVar8 + 1;
          uVar1 = *puVar2;
        }
        psVar6 = (short *)FUN_00059b50(puVar7,lVar8 * 2 + 2);
        *puVar4 = psVar6;
        uVar1 = *param_1;
        puVar7 = param_1;
        lVar8 = lVar3;
        while (uVar1 != 0) {
          puVar7 = puVar7 + 1;
          lVar8 = lVar8 + 1;
          uVar1 = *puVar7;
        }
        uVar5 = FUN_00059244(psVar6,lVar8 + 1,(short *)param_1);
        *(undefined1 *)(puVar4 + 1) = DAT_000b8b5e;
      }
      puVar9[2] = puVar4;
    }
LAB_0008f108:
    lVar3 = CONCAT71((int7)((ulonglong)uVar5 >> 8),(char)lVar3);
  }
  return lVar3;
}

