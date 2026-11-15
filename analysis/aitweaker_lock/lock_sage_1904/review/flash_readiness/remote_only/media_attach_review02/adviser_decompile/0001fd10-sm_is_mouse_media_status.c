
undefined4 sm_is_mouse_media_status(void)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar1 = DAT_0001fd38;
  iVar3 = DAT_0001fd38 + 8;
  acquire_mutex(iVar3);
  uVar2 = *(undefined4 *)(iVar1 + 0x84);
  release_mutex(iVar3);
  return uVar2;
}

