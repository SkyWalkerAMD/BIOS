
void sm_set_media_license_send(void)

{
  int iVar1;
  int iVar2;
  
  iVar1 = DAT_00020f0c;
  iVar2 = DAT_00020f0c + 8;
  acquire_mutex(iVar2);
  *(undefined4 *)(iVar1 + 0x98) = 1;
  release_mutex(iVar2);
  return;
}

