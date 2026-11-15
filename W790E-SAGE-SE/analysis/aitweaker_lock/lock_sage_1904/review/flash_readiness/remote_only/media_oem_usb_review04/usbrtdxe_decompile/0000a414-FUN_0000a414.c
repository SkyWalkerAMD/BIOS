
ulonglong FUN_0000a414(longlong param_1,ulonglong param_2)

{
  undefined2 uVar1;
  ulonglong uVar2;
  
  if (*(char *)(param_1 + 0x58) == '\x04') {
    uVar1 = 2;
    *(undefined1 *)(param_1 + 0x6a) = 0x12;
    *(undefined1 *)(param_1 + 0x70) = 0x12;
  }
  else {
    *(undefined1 *)(param_1 + 0x6a) = 0x3f;
    *(undefined1 *)(param_1 + 0x70) = 0x3f;
    if (param_2 < 0x1f7821) {
      uVar1 = 0x20;
    }
    else if (param_2 < 0x3ef041) {
      uVar1 = 0x40;
    }
    else {
      uVar1 = 0x80;
      if (0x7de080 < param_2) {
        uVar1 = 0xff;
      }
    }
  }
  *(undefined2 *)(param_1 + 0x68) = uVar1;
  *(undefined2 *)(param_1 + 0x6e) = uVar1;
  uVar2 = 0;
  if ((*(char *)(param_1 + 0x6a) != '\0') && (*(short *)(param_1 + 0x68) != 0)) {
    uVar2 = param_2 / ((ulonglong)*(ushort *)(param_1 + 0x68) * (ulonglong)*(byte *)(param_1 + 0x6a)
                      );
  }
  if (uVar2 < 2) {
    uVar2 = uVar2 + 1;
  }
  if (0xffff < uVar2) {
    uVar2 = 0xffff;
  }
  *(short *)(param_1 + 0x6c) = (short)uVar2;
  *(short *)(param_1 + 0x72) = (short)uVar2;
  return uVar2 & 0xffffffffffffff00;
}

