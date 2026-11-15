
undefined4 FUN_00018b0c(undefined4 param_1,void *param_2)

{
  int iVar1;
  void *__ptr;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  bool bVar5;
  
  __ptr = malloc(0x400);
  if (__ptr == (void *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00018c00,DAT_00018bf4,DAT_00018bfc);
    uVar4 = 0xffffffff;
  }
  else {
    iVar2 = sigwrap_open(param_1,0);
    if (iVar2 < 0) {
      free(__ptr);
      sigwrap_close(iVar2);
      uVar4 = 0xffffffff;
    }
    else {
      iVar3 = sigwrap_read(iVar2,__ptr,0x400);
      bVar5 = SCARRY4(iVar3,1);
      iVar1 = iVar3 + 1;
      if (iVar3 != -1) {
        bVar5 = SBORROW4(iVar3,0x400);
        iVar1 = iVar3 + -0x400;
      }
      if (iVar1 < 0 == bVar5) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00018bf8,DAT_00018bf4,DAT_00018bf0);
        sigwrap_close(iVar2);
        free(__ptr);
        uVar4 = 0xffffffff;
      }
      else {
        sigwrap_close(iVar2);
        iVar2 = memcmp(__ptr,param_2,0x14);
        if (iVar2 == 0) {
          free(__ptr);
          uVar4 = 0;
        }
        else {
          free(__ptr);
          uVar4 = 0xffffffff;
        }
      }
    }
  }
  return uVar4;
}

