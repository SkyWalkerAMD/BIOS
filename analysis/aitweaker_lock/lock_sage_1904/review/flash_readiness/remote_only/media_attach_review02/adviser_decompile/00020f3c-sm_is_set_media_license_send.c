
undefined4 sm_is_set_media_license_send(void)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar1 = DAT_00020f64;
  iVar3 = DAT_00020f64 + 8;
  acquire_mutex(iVar3);
  uVar2 = *(undefined4 *)(iVar1 + 0x98);
  release_mutex(iVar3);
  return uVar2;
}

