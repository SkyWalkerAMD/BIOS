
void _FINI_0(void)

{
  if (*(char *)(DAT_00010fb4 + 0x10f70) != '\0') {
    return;
  }
  if (*(int *)(DAT_00010fb8 + 0x10f78 + DAT_00010fbc) != 0) {
    __cxa_finalize(*(undefined4 *)(DAT_00010fc0 + 0x10f9c));
  }
  FUN_00010ea4();
  *(undefined1 *)(DAT_00010fc4 + 0x10fb0) = 1;
  return;
}

