
ulonglong FUN_0000f554(undefined8 *param_1,longlong param_2,short *param_3,longlong param_4)

{
  int iVar1;
  longlong lVar2;
  ulonglong uVar3;
  byte bVar4;
  char *pcVar5;
  ulonglong uVar6;
  longlong lVar7;
  char *local_res10;
  
  lVar7 = 0;
  uVar3 = 0;
  local_res10 = (char *)0x0;
  uVar6 = 0;
  bVar4 = 0;
  if (*(longlong *)(param_2 + 0x330) != 0) {
    do {
      lVar2 = *(longlong *)(*(longlong *)(param_2 + 0x338) + uVar6 * 8);
      if (*(char *)(lVar2 + 0x18) == '\x01') {
        if ((*(byte *)(lVar2 + 0xee) & 0x10) != 0) {
          iVar1 = *(int *)(lVar2 + 0xe0);
          if (iVar1 == 0) {
            bVar4 = bVar4 | 1;
          }
          else if (iVar1 == 1) {
            bVar4 = bVar4 | 2;
          }
          else if (iVar1 == 2) {
            bVar4 = bVar4 | 4;
          }
        }
        uVar3 = FUN_0000f320((byte *)(lVar2 + 0x28),param_1,param_3,lVar2,(longlong *)&local_res10);
        pcVar5 = local_res10;
        if ((longlong)uVar3 < 0) goto LAB_0000f628;
        lVar7 = lVar7 + 1;
      }
      pcVar5 = local_res10;
      uVar6 = uVar6 + 1;
    } while (uVar6 < *(ulonglong *)(param_2 + 0x330));
    if (lVar7 != 0) {
      uVar3 = FUN_0000d3d0(param_4,local_res10,lVar7,bVar4);
    }
LAB_0000f628:
    if (pcVar5 != (char *)0x0) {
      (**(code **)(DAT_0001e070 + 0x48))(pcVar5);
    }
  }
  return uVar3;
}

