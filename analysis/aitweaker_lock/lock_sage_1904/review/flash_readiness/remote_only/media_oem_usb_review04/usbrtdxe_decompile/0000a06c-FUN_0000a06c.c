
undefined8 FUN_0000a06c(longlong param_1,ulonglong param_2,longlong param_3)

{
  ushort uVar1;
  int *piVar2;
  ulonglong uVar3;
  uint local_res18 [2];
  int local_res20 [2];
  int local_38 [4];
  
  uVar3 = 0;
  piVar2 = (int *)0xaa55;
  local_res18[0] = 0;
  local_res20[0] = 0;
  local_38[0] = 0;
  if (*(short *)(param_3 + 0x1fe) != -0x55ab) goto LAB_0000a0a2;
  if (local_res18 == (uint *)(param_3 + 3)) {
LAB_0000a0e0:
    *(undefined1 *)(param_3 + 0x39) = 0x20;
    if (local_res20 != (int *)(param_3 + 0x36)) {
      FUN_00000280((undefined8 *)local_res20,(undefined8 *)(param_3 + 0x36),4);
    }
    piVar2 = local_38;
    if (piVar2 != (int *)(param_3 + 0x52)) {
      piVar2 = (int *)FUN_00000280((undefined8 *)local_38,(undefined8 *)(param_3 + 0x52),4);
    }
    if ((local_res20[0] != 0x20544146) && (local_38[0] != 0x33544146)) goto LAB_0000a0a2;
  }
  else {
    FUN_00000280((undefined8 *)local_res18,(undefined8 *)(param_3 + 3),4);
    piVar2 = (int *)(ulonglong)local_res18[0];
    if (((local_res18[0] != 0x4f44534d) && (local_res18[0] != 0x4957534d)) &&
       (local_res18[0] != 0x5346544e)) goto LAB_0000a0e0;
  }
  if (*(short *)(param_3 + 0x18) != 0) {
    *(undefined1 *)(param_1 + 0x6a) = *(undefined1 *)(param_3 + 0x18);
    piVar2 = (int *)CONCAT71((int7)((ulonglong)piVar2 >> 8),*(undefined1 *)(param_3 + 0x18));
    *(undefined1 *)(param_1 + 0x70) = *(undefined1 *)(param_3 + 0x18);
    uVar1 = *(ushort *)(param_3 + 0x1a);
    if (uVar1 != 0) {
      *(ushort *)(param_1 + 0x68) = uVar1;
      *(undefined2 *)(param_1 + 0x6e) = *(undefined2 *)(param_3 + 0x1a);
      *(undefined1 *)(param_1 + 0x136) = *(undefined1 *)(param_3 + 0x15);
      if ((*(char *)(param_1 + 0x6a) != '\0') && (uVar1 != 0)) {
        uVar3 = param_2 / ((ulonglong)uVar1 * (ulonglong)*(byte *)(param_1 + 0x6a));
      }
      if (uVar3 < 2) {
        uVar3 = uVar3 + 1;
      }
      if (0xffff < uVar3) {
        uVar3 = 0xffff;
      }
      *(short *)(param_1 + 0x6c) = (short)uVar3;
      *(short *)(param_1 + 0x72) = (short)uVar3;
      return 0xff00;
    }
  }
LAB_0000a0a2:
  return CONCAT71((int7)((ulonglong)piVar2 >> 8),0xff);
}

