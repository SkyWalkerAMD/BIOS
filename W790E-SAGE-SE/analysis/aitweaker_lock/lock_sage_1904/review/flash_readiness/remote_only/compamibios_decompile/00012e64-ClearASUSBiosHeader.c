
void ClearASUSBiosHeader(void)

{
  if (*(void **)((int)DAT_00012edc + 0xcb) != (void *)0x0) {
    free(*(void **)((int)DAT_00012edc + 0xcb));
  }
  memset(DAT_00012edc,0,0xd7);
  if (*(void **)((int)DAT_00012ee0 + 0xcb) != (void *)0x0) {
    free(*(void **)((int)DAT_00012ee0 + 0xcb));
  }
  memset(DAT_00012ee0,0,0xd7);
  return;
}

