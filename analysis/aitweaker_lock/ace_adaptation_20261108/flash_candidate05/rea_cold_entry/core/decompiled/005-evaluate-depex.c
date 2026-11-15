
char Candidate_ACE1904_evaluate_depex(longlong param_1)

{
  byte bVar1;
  undefined *puVar2;
  byte *pbVar3;
  undefined **ppuVar4;
  longlong lVar5;
  undefined1 uVar6;
  byte *pbVar7;
  byte *pbVar8;
  byte *pbVar9;
  bool bVar10;
  char local_res8 [8];
  char local_res10 [8];
  undefined8 local_res18 [2];
  byte local_38 [16];
  
  local_res8[0] = '\0';
  local_res10[0] = '\0';
  if ((*(char *)(param_1 + 0x61) == '\0') && (*(char *)(param_1 + 0x60) == '\0')) {
    pbVar7 = *(byte **)(param_1 + 0x50);
    if (pbVar7 == (byte *)0x0) {
      ppuVar4 = &PTR_DAT_000162e0;
      puVar2 = PTR_DAT_000162e0;
      while( true ) {
        if (puVar2 == (undefined *)0x0) {
          return '\x01';
        }
        if (*(char *)(ppuVar4 + 4) == '\0') break;
        ppuVar4 = ppuVar4 + 5;
        puVar2 = *ppuVar4;
      }
    }
    else {
      DAT_00017ba8 = DAT_00017b98;
      pbVar8 = pbVar7;
      pbVar3 = pbVar7;
      if (*(longlong *)(param_1 + 0x58) != 0) {
        do {
          pbVar9 = pbVar3 + 1;
          bVar1 = *pbVar8;
          if (bVar1 < 7) {
            if (bVar1 == 6) {
LAB_0000f114:
              bVar10 = true;
            }
            else {
              if (bVar1 < 2) {
LAB_0000f1d9:
                if (pbVar8 != pbVar7) {
                  return '\0';
                }
                goto LAB_0000f1f7;
              }
              if (bVar1 == 2) {
                if (local_38 != pbVar9) {
                  FUN_00000410((undefined8 *)local_38,(undefined8 *)pbVar9,0x10);
                }
                lVar5 = FUN_0000abbc((longlong *)local_38,0,local_res18);
                if (-1 < lVar5) {
                  *pbVar8 = 0xff;
                  goto LAB_0000f18f;
                }
                uVar6 = 0;
                goto LAB_0000f191;
              }
              if (bVar1 == 3) {
                lVar5 = FUN_0000efd8(local_res8);
                if (lVar5 < 0) {
                  return '\0';
                }
                lVar5 = FUN_0000efd8(local_res10);
                if (lVar5 < 0) {
                  return '\0';
                }
                if ((local_res8[0] == '\0') || (bVar10 = true, local_res10[0] == '\0')) {
                  bVar10 = false;
                }
              }
              else if (bVar1 == 4) {
                lVar5 = FUN_0000efd8(local_res8);
                if (lVar5 < 0) {
                  return '\0';
                }
                lVar5 = FUN_0000efd8(local_res10);
                if (lVar5 < 0) {
                  return '\0';
                }
                if ((local_res8[0] != '\0') || (bVar10 = false, local_res10[0] != '\0'))
                goto LAB_0000f114;
              }
              else {
                if (bVar1 != 5) {
                  return '\0';
                }
                lVar5 = FUN_0000efd8(local_res8);
                if (lVar5 < 0) {
                  return '\0';
                }
                bVar10 = local_res8[0] == '\0';
              }
            }
LAB_0000f1ed:
            lVar5 = FUN_0000ef98(bVar10);
            if (lVar5 < 0) {
              return '\0';
            }
          }
          else {
            if (bVar1 == 7) {
              bVar10 = false;
              goto LAB_0000f1ed;
            }
            if (bVar1 == 8) {
              lVar5 = FUN_0000efd8(local_res8);
              if (lVar5 < 0) {
                return '\0';
              }
              return local_res8[0];
            }
            if (bVar1 == 9) goto LAB_0000f1d9;
            if (bVar1 != 0xff) {
              return '\0';
            }
            if (local_38 != pbVar9) {
              FUN_00000410((undefined8 *)local_38,(undefined8 *)pbVar9,0x10);
            }
LAB_0000f18f:
            uVar6 = 1;
LAB_0000f191:
            lVar5 = FUN_0000ef98(uVar6);
            if (lVar5 < 0) {
              return '\0';
            }
            pbVar8 = pbVar8 + 0x10;
            pbVar9 = pbVar3 + 0x11;
          }
LAB_0000f1f7:
          pbVar7 = *(byte **)(param_1 + 0x50);
          pbVar8 = pbVar8 + 1;
          pbVar3 = pbVar9;
        } while ((ulonglong)((longlong)pbVar8 - (longlong)pbVar7) < *(ulonglong *)(param_1 + 0x58));
      }
    }
  }
  return '\0';
}

