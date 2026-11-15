
void _FINI_0(void)

{
  if (*(char *)(DAT_00010f80 + 0x10f3c) != '\0') {
    return;
  }
  if (*(int *)(DAT_00010f84 + 0x10f44 + DAT_00010f88) != 0) {
    __cxa_finalize(*(undefined4 *)(DAT_00010f8c + 0x10f68));
  }
  FUN_00010e70();
  *(undefined1 *)(DAT_00010f90 + 0x10f7c) = 1;
  return;
}

