
undefined4 verify_bios_img(int param_1,int param_2,uint param_3,undefined4 *param_4)

{
  int iVar1;
  int __fd;
  char *__ptr;
  char *__ptr_00;
  __off_t _Var2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  char *pcVar6;
  size_t __size;
  undefined4 uVar7;
  uint __offset;
  uint uVar8;
  int iVar9;
  
  __fd = sigwrap_open(DAT_00011b9c,2);
  iVar1 = DAT_00011ba0;
  uVar4 = DAT_00011bdc;
  uVar7 = DAT_00011bd8;
  if (-1 < __fd) {
    __size = *(size_t *)(DAT_00011ba0 + 0x1c);
    __ptr = malloc(__size);
    uVar4 = DAT_00011be4;
    uVar7 = DAT_00011be0;
    if (__ptr != (char *)0x0) {
      __ptr_00 = malloc(__size);
      if (__ptr_00 == (char *)0x0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00011be4,DAT_00011bac,DAT_00011be8);
        sigwrap_close(__fd);
        free(__ptr);
        *param_4 = 0xffffffff;
        return 0xffffffff;
      }
      if (__size <= param_3) {
        __offset = 0;
        uVar8 = __offset;
        do {
          _Var2 = lseek(param_1,__offset + param_2,0);
          if (_Var2 == -1) {
            pcVar6 = strerror(0);
            uVar4 = DAT_00011bc0;
LAB_00011ac0:
            uVar7 = 0xffffffff;
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00011bc4,DAT_00011bac,uVar4,pcVar6);
            *param_4 = 0xffffffff;
            goto LAB_00011a50;
          }
          _Var2 = lseek(__fd,__offset,0);
          if (_Var2 == -1) {
            pcVar6 = strerror(0);
            uVar4 = DAT_00011bc8;
            goto LAB_00011ac0;
          }
          iVar3 = sigwrap_read(param_1,__ptr,*(undefined4 *)(iVar1 + 0x1c));
          if (iVar3 != *(int *)(iVar1 + 0x1c)) {
            pcVar6 = strerror(0);
            uVar4 = DAT_00011bcc;
LAB_00011b00:
            uVar7 = 0xffffffff;
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00011bd0,DAT_00011bac,uVar4,pcVar6);
            *param_4 = 0xffffffff;
            goto LAB_00011a50;
          }
          iVar3 = sigwrap_read(__fd,__ptr_00,iVar3);
          iVar9 = *(int *)(iVar1 + 0x1c);
          if (iVar3 != iVar9) {
            pcVar6 = strerror(0);
            uVar4 = DAT_00011bd4;
            goto LAB_00011b00;
          }
          if (iVar9 < 1) {
            if (iVar9 != 0) {
              IDBG_LINUXAPP_DbgOut(0x86,DAT_00011bb8,__offset);
              IDBG_LINUXAPP_DbgOut(0x86,DAT_00011bbc);
              uVar7 = 0;
              *param_4 = 0xffffffff;
              goto LAB_00011a50;
            }
          }
          else {
            if (*__ptr_00 != *__ptr) {
              iVar3 = 0;
LAB_00011a2c:
              uVar7 = 0xffffffff;
              IDBG_LINUXAPP_DbgOut(0x86,DAT_00011bb0,iVar3);
              IDBG_LINUXAPP_DbgOut(0x86,DAT_00011bb4);
              *param_4 = 0xffffffff;
              goto LAB_00011a50;
            }
            iVar3 = 0;
            while( true ) {
              __ptr = __ptr + 1;
              __ptr_00 = __ptr_00 + 1;
              iVar3 = iVar3 + 1;
              if (iVar9 == iVar3) break;
              if (*__ptr != *__ptr_00) {
                __ptr = __ptr + -iVar3;
                __ptr_00 = __ptr_00 + -iVar3;
                goto LAB_00011a2c;
              }
            }
            __ptr = __ptr + -iVar9;
            __ptr_00 = __ptr_00 + -iVar9;
          }
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00011ba4,uVar8);
          uVar4 = FUN_0001226c(param_3,*(undefined4 *)(iVar1 + 0x1c));
          uVar4 = FUN_0001226c(uVar8 * 100,uVar4);
          *param_4 = uVar4;
          IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011ba8,DAT_00011bac,0x1cc,uVar4);
          __offset = __offset + *(int *)(iVar1 + 0x1c);
          uVar5 = FUN_0001226c(param_3,*(int *)(iVar1 + 0x1c));
          uVar8 = uVar8 + 1;
        } while (uVar8 < uVar5);
      }
      uVar7 = 0;
      *param_4 = 100;
LAB_00011a50:
      free(__ptr);
      free(__ptr_00);
      sigwrap_close(__fd);
      return uVar7;
    }
  }
  IDBG_LINUXAPP_DbgOut(0x82,uVar4,DAT_00011bac,uVar7);
  *param_4 = 0xffffffff;
  return 0xffffffff;
}

