
undefined4 verify_bios_img(int param_1,int param_2,uint param_3,undefined4 *param_4)

{
  int iVar1;
  int __fd;
  char *__ptr;
  char *__ptr_00;
  __off_t _Var2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  uint uVar6;
  char *pcVar7;
  size_t __size;
  uint __offset;
  uint uVar8;
  int iVar9;
  
  __fd = sigwrap_open(DAT_00011a94,2);
  iVar1 = DAT_00011a98;
  if (__fd < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011ac8,DAT_00011aa8,DAT_00011ac4);
    *param_4 = 0xffffffff;
  }
  else {
    __size = *(size_t *)(DAT_00011a98 + 0x1c);
    __ptr = malloc(__size);
    if (__ptr != (char *)0x0) {
      __ptr_00 = malloc(__size);
      if (__ptr_00 != (char *)0x0) {
        if (__size <= param_3) {
          __offset = 0;
          uVar8 = __offset;
          do {
            _Var2 = lseek(param_1,__offset + param_2,0);
            if (_Var2 == -1) {
              pcVar7 = strerror(0);
              uVar4 = 0x1a8;
LAB_000119e4:
              uVar5 = 0xffffffff;
              IDBG_LINUXAPP_DbgOut(0x82,DAT_00011abc,DAT_00011aa8,uVar4,pcVar7);
              *param_4 = 0xffffffff;
              goto LAB_00011974;
            }
            _Var2 = lseek(__fd,__offset,0);
            if (_Var2 == -1) {
              pcVar7 = strerror(0);
              uVar4 = 0x1b0;
              goto LAB_000119e4;
            }
            iVar3 = sigwrap_read(param_1,__ptr,*(undefined4 *)(iVar1 + 0x1c));
            if (iVar3 != *(int *)(iVar1 + 0x1c)) {
              pcVar7 = strerror(0);
              uVar4 = 0x1b8;
LAB_00011a24:
              uVar5 = 0xffffffff;
              IDBG_LINUXAPP_DbgOut(0x82,DAT_00011ac0,DAT_00011aa8,uVar4,pcVar7);
              *param_4 = 0xffffffff;
              goto LAB_00011974;
            }
            iVar3 = sigwrap_read(__fd,__ptr_00,iVar3);
            iVar9 = *(int *)(iVar1 + 0x1c);
            if (iVar3 != iVar9) {
              pcVar7 = strerror(0);
              uVar4 = 0x1c0;
              goto LAB_00011a24;
            }
            if (iVar9 < 1) {
              if (iVar9 != 0) {
                IDBG_LINUXAPP_DbgOut(0x86,DAT_00011ab4,__offset);
                IDBG_LINUXAPP_DbgOut(0x86,DAT_00011ab8);
                uVar5 = 0;
                *param_4 = 0xffffffff;
                goto LAB_00011974;
              }
            }
            else {
              if (*__ptr_00 != *__ptr) {
                iVar3 = 0;
LAB_00011950:
                uVar5 = 0xffffffff;
                IDBG_LINUXAPP_DbgOut(0x86,DAT_00011aac,iVar3);
                IDBG_LINUXAPP_DbgOut(0x86,DAT_00011ab0);
                *param_4 = 0xffffffff;
                goto LAB_00011974;
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
                  goto LAB_00011950;
                }
              }
              __ptr = __ptr + -iVar9;
              __ptr_00 = __ptr_00 + -iVar9;
            }
            IDBG_LINUXAPP_DbgOut(0x86,DAT_00011a9c,uVar8);
            uVar4 = FUN_00011dac(param_3,*(undefined4 *)(iVar1 + 0x1c));
            uVar5 = FUN_00011dac(uVar8 * 100,uVar4);
            uVar4 = DAT_00011aa0;
            *param_4 = uVar5;
            IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011aa4,DAT_00011aa8,uVar4,uVar5);
            __offset = __offset + *(int *)(iVar1 + 0x1c);
            uVar6 = FUN_00011dac(param_3,*(int *)(iVar1 + 0x1c));
            uVar8 = uVar8 + 1;
          } while (uVar8 < uVar6);
        }
        uVar5 = 0;
        *param_4 = 100;
LAB_00011974:
        free(__ptr);
        free(__ptr_00);
        sigwrap_close(__fd);
        return uVar5;
      }
      free(__ptr);
    }
    *param_4 = 0xffffffff;
  }
  return 0xffffffff;
}

