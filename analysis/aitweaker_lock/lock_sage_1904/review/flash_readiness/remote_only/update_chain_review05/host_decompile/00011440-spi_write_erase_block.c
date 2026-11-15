
undefined4 spi_write_erase_block(int param_1,char *param_2,__off_t param_3)

{
  int iVar1;
  char *__ptr;
  __off_t _Var2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  __off_t local_28;
  int local_24;
  
  iVar1 = DAT_00011678;
  __ptr = malloc(*(size_t *)(DAT_00011678 + 0x1c));
  if (__ptr == (char *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011694,DAT_00011680,0xd7);
    return 0xffffffff;
  }
  _Var2 = lseek(param_1,param_3,0);
  if (_Var2 == -1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011698,DAT_00011680,0xdf,param_3);
  }
  else {
    iVar3 = sigwrap_read(param_1,__ptr,*(undefined4 *)(iVar1 + 0x1c));
    iVar5 = *(int *)(iVar1 + 0x1c);
    if (iVar3 == iVar5) {
      if (iVar5 < 1) {
        if (iVar5 == 0) {
LAB_000114f4:
          free(__ptr);
          uVar4 = FUN_0001226c(param_3,iVar3);
          IDBG_LINUXAPP_DbgOut(0x86,DAT_0001167c,uVar4);
          return 0;
        }
      }
      else if (*__ptr == *param_2) {
        iVar3 = 0;
        do {
          param_2 = param_2 + 1;
          __ptr = __ptr + 1;
          iVar3 = iVar3 + 1;
          if (iVar5 == iVar3) {
            __ptr = __ptr + -iVar5;
            iVar3 = iVar5;
            goto LAB_000114f4;
          }
        } while (*__ptr == *param_2);
        param_2 = param_2 + -iVar3;
        __ptr = __ptr + -iVar3;
      }
      free(__ptr);
      local_28 = param_3;
      local_24 = iVar5;
      uVar4 = FUN_0001226c(param_3,iVar5);
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00011688,uVar4);
      iVar3 = ioctl(param_1,DAT_0001168c,&local_28);
      if (iVar3 == -1) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000116a8,DAT_00011680,DAT_000116a4);
        return 0xffffffff;
      }
      _Var2 = lseek(param_1,param_3,0);
      if (_Var2 != -1) {
        iVar3 = sigwrap_write(param_1,param_2,*(undefined4 *)(iVar1 + 0x1c));
        if (iVar3 != *(int *)(iVar1 + 0x1c)) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00011690,DAT_00011680,0x11c);
          return 0xffffffff;
        }
        return 0;
      }
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000116a0,DAT_00011680,DAT_0001169c);
      return 0xffffffff;
    }
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011684,DAT_00011680,0xe5);
  }
  free(__ptr);
  return 0xffffffff;
}

