
void _FINI_0(void)

{
  if (*(char *)(DAT_00010ea0 + 0x10e5c) != '\0') {
    return;
  }
  if (*(int *)(DAT_00010ea4 + 0x10e64 + DAT_00010ea8) != 0) {
    __cxa_finalize(*(undefined4 *)(DAT_00010eac + 0x10e88));
  }
  FUN_00010d90();
  *(undefined1 *)(DAT_00010eb0 + 0x10e9c) = 1;
  return;
}

