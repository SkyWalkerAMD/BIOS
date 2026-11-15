
undefined1 FUN_0006d658(longlong param_1)

{
  byte bVar1;
  char *pcVar2;
  undefined1 uVar3;
  
  uVar3 = 0;
  if (param_1 != 0) {
    if ((*(byte *)(param_1 + 0x1c) & 1) != 0) {
      bVar1 = FUN_00036f08(param_1);
      if (bVar1 == 0) {
        return 0;
      }
      pcVar2 = *(char **)(param_1 + 0x30);
      if (pcVar2 == (char *)0x0) {
        return 0;
      }
      if (*pcVar2 != '\x1e') {
        return 0;
      }
      pcVar2 = pcVar2 + ((byte)pcVar2[1] & 0x7f);
      if (pcVar2 == (char *)0x0) {
        return 0;
      }
      if (*pcVar2 != 'F') {
        return 0;
      }
      bVar1 = pcVar2[(byte)pcVar2[1] & 0x7f];
      if (((0x23 < bVar1) || ((0x81c00b1ecU >> ((ulonglong)bVar1 & 0x3f) & 1) == 0)) &&
         (bVar1 != 0x5f)) {
        return 0;
      }
    }
    uVar3 = 1;
  }
  return uVar3;
}

