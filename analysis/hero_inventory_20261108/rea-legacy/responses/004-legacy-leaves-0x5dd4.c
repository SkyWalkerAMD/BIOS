
byte * FUN_00005ba8(undefined8 *param_1,longlong param_2,short *param_3,longlong *param_4)

{
  byte bVar1;
  longlong lVar2;
  short *psVar3;
  byte *pbVar4;
  byte *pbVar5;
  byte *pbVar6;
  byte *pbVar7;
  undefined8 *puVar8;
  short *psVar9;
  ulonglong uVar10;
  byte *pbVar11;
  short *local_48;
  byte *local_40;
  
  pbVar7 = (byte *)0x0;
  local_40 = (byte *)0x0;
  local_48 = (short *)0x0;
  pbVar6 = pbVar7;
  pbVar11 = pbVar7;
  if (*(longlong *)(param_2 + 0x330) != 0) {
    do {
      pbVar4 = (byte *)0x0;
      lVar2 = *(longlong *)(*(longlong *)(param_2 + 0x338) + (longlong)pbVar11 * 8);
      if (*(char *)(lVar2 + 0x18) == '\b') {
        if (*(short *)(lVar2 + 0x158) != 0) {
          if (((*(byte *)(lVar2 + 0x159) & 1) == 0) || ((*(byte *)(lVar2 + 0x159) & 2) == 0)) {
            return (byte *)0x800000000000000e;
          }
          puVar8 = (undefined8 *)0x0;
          pbVar7 = (byte *)0x0;
          if ((param_1 == (undefined8 *)0x0) || (param_3 == (short *)0x0)) {
            pbVar5 = (byte *)0x8000000000000002;
          }
          else {
            puVar8 = (undefined8 *)FUN_00016b80();
            if (puVar8 == (undefined8 *)0x0) {
LAB_00005c6a:
              pbVar5 = (byte *)0x8000000000000009;
              pbVar7 = pbVar4;
            }
            else {
              *(undefined4 *)(puVar8 + 3) = 6;
              pbVar5 = (byte *)FUN_00011560((byte *)(lVar2 + 0x28),(longlong)puVar8);
              pbVar7 = pbVar4;
              if ((-1 < (longlong)pbVar5) &&
                 (pbVar5 = (byte *)FUN_00010d78(lVar2 + 0x28,(longlong)puVar8,0,param_4),
                 -1 < (longlong)pbVar5)) {
                pbVar4 = FUN_0001784c((longlong)puVar8,0,1,(longlong *)0x0);
                uVar10 = 0;
                if (pbVar4 == (byte *)0x0) goto LAB_00005c6a;
                bVar1 = *pbVar4;
                while (bVar1 != 0) {
                  uVar10 = uVar10 + 1;
                  bVar1 = pbVar4[uVar10];
                }
                pbVar5 = (byte *)FUN_00019384(param_1,param_3,(char *)pbVar4,uVar10,&local_40);
                pbVar6 = local_40;
                pbVar7 = pbVar4;
              }
            }
          }
          if (puVar8 != (undefined8 *)0x0) {
            FUN_00016bcc(puVar8);
          }
          if (pbVar7 != (byte *)0x0) {
            (**(code **)(DAT_0001e070 + 0x48))(pbVar7);
          }
          if ((longlong)pbVar5 < 0) {
            return pbVar5;
          }
          pbVar4 = (byte *)FUN_00000854(param_1,pbVar6,s_MemoryChunks_0001ac98,&local_48);
          psVar3 = local_48;
          pbVar7 = (byte *)0x0;
          if ((longlong)pbVar4 < 0) {
            if (pbVar6 == (byte *)0x0) {
              return pbVar4;
            }
            (**(code **)(DAT_0001e070 + 0x48))(pbVar6);
            return pbVar4;
          }
          if (((param_1 == (undefined8 *)0x0) || (local_48 == (short *)0x0)) ||
             (param_4 == (longlong *)0x0)) {
            pbVar7 = (byte *)0x8000000000000002;
          }
          else if (*(char *)(lVar2 + 0x2f) != '\0') {
            psVar9 = (short *)(lVar2 + 0x192);
            pbVar4 = pbVar7;
            do {
              if (((byte *)((longlong)&IMAGE_DOS_HEADER_00000000.e_minalloc + 1) < pbVar4) ||
                 ((((char)psVar9[-0x10] != '\0' && (*psVar9 != 0)) &&
                  (pbVar7 = (byte *)FUN_00005a74((byte *)(psVar9 + -0x11),param_1,psVar3,param_4),
                  (longlong)pbVar7 < 0)))) break;
              pbVar4 = pbVar4 + 1;
              psVar9 = psVar9 + 0x174;
            } while (pbVar4 < (byte *)(ulonglong)*(byte *)(lVar2 + 0x2f));
          }
          if (psVar3 != (short *)0x0) {
            (**(code **)(DAT_0001e070 + 0x48))(psVar3);
            local_48 = (short *)0x0;
          }
          if (pbVar6 != (byte *)0x0) {
            (**(code **)(DAT_0001e070 + 0x48))(pbVar6);
            pbVar6 = (byte *)0x0;
            local_40 = (byte *)0x0;
          }
          if ((longlong)pbVar7 < 0) {
            return pbVar7;
          }
          goto LAB_00005e30;
        }
      }
      else {
LAB_00005e30:
        pbVar11 = pbVar11 + 1;
      }
    } while (pbVar11 < *(byte **)(param_2 + 0x330));
  }
  return pbVar7;
}

