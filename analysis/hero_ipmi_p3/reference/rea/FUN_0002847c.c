
byte * FUN_0002847c(longlong param_1,uint *param_2,undefined8 *param_3)

{
  byte *pbVar1;
  byte *pbVar2;
  uint *puVar3;
  uint uVar4;
  longlong lVar5;
  ulonglong uVar6;
  byte *pbVar7;
  uint uVar8;
  longlong *plVar9;
  byte bVar10;
  char cVar11;
  char cVar12;
  longlong *plVar13;
  longlong local_68 [6];
  byte *local_38;
  
  pbVar1 = *(byte **)(param_1 + 0x30);
  pbVar2 = *(byte **)(param_1 + 0x28);
  if ((pbVar1 == (byte *)0x0) || (pbVar2 <= pbVar1)) {
    pbVar7 = (byte *)0x0;
  }
  else {
    bVar10 = *pbVar1;
    pbVar7 = pbVar1;
    cVar11 = '\0';
    if ((bVar10 == 10) || (bVar10 == 0x19)) {
      do {
        cVar12 = cVar11 + '\x01';
        if (pbVar7[1] < 0x80) {
          cVar12 = cVar11;
        }
        if ((bVar10 == 0x29) && (cVar12 = cVar12 + -1, cVar12 == '\0')) goto LAB_0002861c;
        pbVar7 = pbVar7 + (pbVar7[1] & 0x7f);
        bVar10 = *pbVar7;
        cVar11 = cVar12;
      } while ((bVar10 - 0x12 & 0xfd) != 0);
    }
    if ((*param_2 < *DAT_001937f0) &&
       (plVar13 = (longlong *)
                  ((ulonglong)DAT_001937f0[(ulonglong)*param_2 + 1] + (longlong)DAT_001937f0),
       plVar13 != (longlong *)0x0)) {
      uVar8 = 0;
      uVar4 = *DAT_00193790;
      puVar3 = DAT_00193790;
      if (uVar4 != 0) {
        do {
          plVar9 = (longlong *)((ulonglong)puVar3[1] + (longlong)DAT_00193790);
          lVar5 = FUN_000b1b20(plVar13,plVar9,0x10);
          if (lVar5 == 0) {
            if (plVar9 != (longlong *)0x0) {
              if (param_3 != (undefined8 *)0x0) {
                *param_3 = plVar9;
              }
              goto LAB_0002858d;
            }
            break;
          }
          uVar8 = uVar8 + 1;
          puVar3 = puVar3 + 1;
        } while (uVar8 < uVar4);
      }
      pbVar7 = (byte *)0x0;
LAB_0002858d:
      if (((pbVar7 == (byte *)0x0) && (uVar6 = FUN_0003c384(pbVar1), uVar6 != 0)) &&
         (pbVar1 + uVar6 < pbVar2)) {
        (**(code **)(DAT_00180188 + 0x160))(local_68,param_1,0x40);
        local_38 = pbVar1 + uVar6;
        uVar4 = FUN_00028250(local_68);
        *param_2 = uVar4 & 0xffff;
        pbVar7 = FUN_0002847c((longlong)local_68,param_2,param_3);
      }
    }
    else {
LAB_0002861c:
      pbVar7 = (byte *)0x0;
    }
  }
  return pbVar7;
}

