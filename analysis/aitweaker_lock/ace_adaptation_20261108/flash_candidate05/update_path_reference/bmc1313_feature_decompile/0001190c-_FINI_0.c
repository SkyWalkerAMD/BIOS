
void _FINI_0(void)

{
  if (*(char *)(DAT_00011960 + 0x1191c) != '\0') {
    return;
  }
  if (*(int *)(DAT_00011964 + 0x11924 + DAT_00011968) != 0) {
    __cxa_finalize(*(undefined4 *)(DAT_0001196c + 0x11948));
  }
  FUN_00011850();
  *(undefined1 *)(DAT_00011970 + 0x1195c) = 1;
  return;
}

