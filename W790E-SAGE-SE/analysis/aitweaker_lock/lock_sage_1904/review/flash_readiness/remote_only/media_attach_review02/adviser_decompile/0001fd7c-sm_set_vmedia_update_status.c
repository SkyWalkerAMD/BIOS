
void sm_set_vmedia_update_status(void)

{
  int iVar1;
  int iVar2;
  
  iVar1 = DAT_0001fda4;
  iVar2 = DAT_0001fda4 + 8;
  acquire_mutex(iVar2);
  *(undefined2 *)(iVar1 + 0x88) = 1;
  release_mutex(iVar2);
  return;
}

