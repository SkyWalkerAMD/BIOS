void FUN_0002ce68(byte param_1,char *param_2,undefined2 *param_3,char *param_4,longlong param_5)
{
  char cVar1;
  char *pcVar2;
  undefined2 uVar3;
  longlong lVar4;
  longlong lVar5;
  if (param_1 < 6) {
    if (param_1 != 5) {
      if (param_1 == 0) {
        cVar1 = *param_2;
        *param_3 = 1;
        *param_4 = cVar1;
        return;
      }
      if (param_1 == 1) {
LAB_0002cfe5:
        uVar3 = *(undefined2 *)param_2;
        *param_3 = 2;
        *(undefined2 *)param_4 = uVar3;
        return;
      }
      if (param_1 == 2) {
        *param_3 = 4;
        *(undefined4 *)param_4 = *(undefined4 *)param_2;
        return;
      }
      if (param_1 == 3) {
        *param_3 = 8;
        *(undefined8 *)param_4 = *(undefined8 *)param_2;
        return;
      }
      if (param_1 != 4) {
LAB_0002cf19:
        *param_3 = 0;
        *param_4 = '\0';
        return;
      }
      *param_3 = 1;
      uVar3 = 1;
      goto LAB_0002d008;
    }
    uVar3 = 3;
  }
  else {
    if (param_1 != 6) {
      if (param_1 == 7) goto LAB_0002cfe5;
      if (param_1 == 8) {
        *param_3 = 0;
        if (*(byte *)(param_5 + 1) < 0x80) {
          return;
        }
        pcVar2 = (char *)((ulonglong)(*(byte *)(param_5 + 1) & 0x7f) + param_5);
        lVar5 = 1;
        if (0x7f < (byte)pcVar2[1]) {
          lVar5 = 2;
          lVar4 = 2;
          if (*pcVar2 == 'Z') {
            pcVar2 = pcVar2 + ((byte)pcVar2[1] & 0x7f);
            cVar1 = *pcVar2;
            if (cVar1 == 'B') {
              *param_4 = pcVar2[2];
              *param_3 = 1;
              lVar5 = lVar4;
            }
            else if (cVar1 == 'C') {
              *(undefined2 *)param_4 = *(undefined2 *)(pcVar2 + 2);
              *param_3 = 2;
              lVar5 = lVar4;
            }
            else if (cVar1 == 'D') {
              *param_3 = 4;
              *(undefined4 *)param_4 = *(undefined4 *)(pcVar2 + 2);
              lVar5 = lVar4;
            }
            else if (cVar1 == 'E') {
              *param_3 = 8;
              *(undefined8 *)param_4 = *(undefined8 *)(pcVar2 + 2);
            }
            else {
              *param_3 = 0;
            }
          }
        }
        do {
          pcVar2 = pcVar2 + ((byte)pcVar2[1] & 0x7f);
          lVar4 = lVar5 + -1;
          if (*pcVar2 != ')') {
            lVar4 = lVar5;
          }
          lVar5 = lVar4;
        } while (lVar4 != 0);
        return;
      }
      if ((param_1 != 0xb) && (param_1 != 0xc)) goto LAB_0002cf19;
      uVar3 = *param_3;
      goto LAB_0002d008;
    }
    uVar3 = 4;
  }
  *param_3 = uVar3;
LAB_0002d008:
  (**(code **)(DAT_00180188 + 0x160))(param_4,param_2,uVar3);
  return;
}
