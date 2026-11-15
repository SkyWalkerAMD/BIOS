
void FUN_00005e7c(undefined8 *param_1,longlong param_2,short *param_3,longlong param_4,
                 longlong *param_5)

{
  int iVar1;
  longlong lVar2;
  longlong lVar3;
  ulonglong uVar4;
  char *pcVar5;
  char *pcVar6;
  byte bVar7;
  ulonglong uVar8;
  byte bVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  undefined8 local_res10;
  short *local_res18;
  longlong local_res20;
  ulonglong local_58;
  ulonglong local_50 [2];
  
  uVar8 = 0;
  local_58 = 0;
  local_50[0] = 0;
  bVar7 = 0;
  bVar9 = 0;
  uVar10 = uVar8;
  uVar11 = uVar8;
  local_res18 = param_3;
  local_res20 = param_4;
  if (*(longlong *)(param_2 + 0x330) != 0) {
    do {
      local_res10 = 0;
      lVar2 = *(longlong *)(*(longlong *)(param_2 + 0x338) + uVar8 * 8);
      if (*(char *)(lVar2 + 0x18) == '\x02') {
        bVar7 = bVar9;
        if (*(longlong *)(lVar2 + 0x148) != 0) {
          if ((*(byte *)(lVar2 + 0x14d) & 1) != 0) {
            iVar1 = *(int *)(lVar2 + 0x130);
            if (iVar1 == 0) {
              bVar9 = bVar9 | 1;
            }
            else if (iVar1 == 1) {
              bVar9 = bVar9 | 2;
            }
            else if (iVar1 == 2) {
              bVar9 = bVar9 | 4;
            }
          }
          uVar4 = FUN_0000586c((byte *)(lVar2 + 0x28),param_1,param_3,param_3,(longlong *)&local_58,
                               (longlong *)local_50,&local_res10);
          if ((longlong)uVar4 < 0) {
            return;
          }
          param_3 = local_res18;
          if (uVar10 < (ulonglong)param_5[1]) {
            lVar3 = *param_5;
            *(undefined8 *)(uVar11 + lVar3) =
                 *(undefined8 *)(*(longlong *)(*(longlong *)(param_2 + 0x338) + uVar8 * 8) + 0x10);
            *(undefined8 *)(uVar11 + 8 + lVar3) = local_res10;
            *(undefined2 *)(uVar11 + 0x10 + lVar3) = *(undefined2 *)(lVar2 + 0x140);
            pcVar5 = (char *)(lVar3 + 0x12 + uVar11);
            for (pcVar6 = *(char **)(lVar2 + 0x3d8); *pcVar6 != '\0'; pcVar6 = pcVar6 + 1) {
              *pcVar5 = *pcVar6;
              pcVar5 = pcVar5 + 1;
            }
            uVar10 = uVar10 + 1;
            *pcVar5 = '\0';
            uVar11 = uVar11 + 0x48;
          }
          goto LAB_00005fd3;
        }
      }
      else {
LAB_00005fd3:
        uVar8 = uVar8 + 1;
        bVar7 = bVar9;
      }
      bVar9 = bVar7;
    } while (uVar8 < *(ulonglong *)(param_2 + 0x330));
  }
  local_res10 = 0;
  FUN_00011850(local_res20,local_58,local_50[0],bVar7);
  return;
}

