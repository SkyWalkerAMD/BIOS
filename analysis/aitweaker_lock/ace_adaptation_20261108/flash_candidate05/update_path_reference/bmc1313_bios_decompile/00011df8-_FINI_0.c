
void _FINI_0(void)

{
  if (*(char *)(DAT_00011e4c + 0x11e08) != '\0') {
    return;
  }
  if (*(int *)(DAT_00011e50 + 0x11e10 + DAT_00011e54) != 0) {
    __cxa_finalize(*(undefined4 *)(DAT_00011e58 + 0x11e34));
  }
  FUN_00011d3c();
  *(undefined1 *)(DAT_00011e5c + 0x11e48) = 1;
  return;
}

