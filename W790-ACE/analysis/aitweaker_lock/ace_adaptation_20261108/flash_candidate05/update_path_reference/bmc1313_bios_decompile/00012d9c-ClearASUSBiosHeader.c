
void ClearASUSBiosHeader(void)

{
  if (*(void **)((int)DAT_00012e14 + 0xcb) != (void *)0x0) {
    free(*(void **)((int)DAT_00012e14 + 0xcb));
  }
  memset(DAT_00012e14,0,0xd7);
  if (*(void **)((int)DAT_00012e18 + 0xcb) != (void *)0x0) {
    free(*(void **)((int)DAT_00012e18 + 0xcb));
  }
  memset(DAT_00012e18,0,0xd7);
  return;
}

