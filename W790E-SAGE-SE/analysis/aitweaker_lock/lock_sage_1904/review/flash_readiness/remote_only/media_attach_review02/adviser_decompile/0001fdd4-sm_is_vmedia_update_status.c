
undefined2 sm_is_vmedia_update_status(void)

{
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = DAT_0001fdfc;
  iVar3 = DAT_0001fdfc + 8;
  acquire_mutex(iVar3);
  uVar1 = *(undefined2 *)(iVar2 + 0x88);
  release_mutex(iVar3);
  return uVar1;
}

