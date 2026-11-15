
void sm_reset_mouse_media_status(void)

{
  int iVar1;
  int iVar2;
  
  iVar1 = DAT_0001fd78;
  iVar2 = DAT_0001fd78 + 8;
  acquire_mutex(iVar2);
  *(undefined4 *)(iVar1 + 0x84) = 0;
  release_mutex(iVar2);
  return;
}

