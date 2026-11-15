
undefined4
verify_bios_img(int param_1,int param_2,undefined4 param_3,undefined4 *param_4,undefined4 param_5)

{
  int __fd;
  char *__ptr;
  char *__ptr_00;
  __off_t _Var1;
  char *pcVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  size_t __size;
  uint __offset;
  uint uVar12;
  
  iVar10 = DAT_00012288 + 0x11f44;
  __fd = sigwrap_open(param_5,2);
  if (__fd < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00012290 + 0x11f78,DAT_0001228c + 0x11f74,0x21f);
LAB_00011f78:
    uVar11 = 0xffffffff;
    *param_4 = 0xffffffff;
  }
  else {
    iVar10 = *(int *)(iVar10 + DAT_00012294);
    __size = *(size_t *)(iVar10 + 0x1c);
    __ptr = malloc(__size);
    if (__ptr == (char *)0x0) {
      uVar11 = 0xffffffff;
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001229c + 0x11fcc,DAT_00012298 + 0x11fc4,0x227);
      *param_4 = 0xffffffff;
    }
    else {
      __ptr_00 = malloc(__size);
      if (__ptr_00 == (char *)0x0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000122a4 + 0x12008,DAT_000122a0 + 0x12004,0x230);
        sigwrap_close(__fd);
        free(__ptr);
        goto LAB_00011f78;
      }
      iVar7 = DAT_000122d8 + 0x1226c;
      iVar8 = DAT_000122dc + 0x12278;
      iVar9 = DAT_000122e0 + 0x12284;
      __offset = 0;
      for (uVar12 = __offset; uVar4 = FUN_00012acc(param_3,*(undefined4 *)(iVar10 + 0x1c)),
          uVar12 < uVar4; uVar12 = uVar12 + 1) {
        _Var1 = lseek(param_1,__offset + param_2,0);
        if (_Var1 == -1) {
          pcVar2 = strerror(0);
          uVar11 = 0x23c;
          iVar7 = DAT_000122a8 + 0x12058;
          iVar10 = DAT_000122ac + 0x12060;
LAB_0001205c:
          IDBG_LINUXAPP_DbgOut(0x82,iVar10,iVar7,uVar11,pcVar2);
LAB_00012064:
          uVar11 = 0xffffffff;
          *param_4 = 0xffffffff;
          goto LAB_00012068;
        }
        _Var1 = lseek(__fd,__offset,0);
        if (_Var1 == -1) {
          pcVar2 = strerror(0);
          uVar11 = 0x244;
          iVar7 = DAT_000122b0 + 0x120b4;
          iVar10 = DAT_000122b4 + 0x120bc;
          goto LAB_0001205c;
        }
        iVar3 = sigwrap_read(param_1,__ptr,*(undefined4 *)(iVar10 + 0x1c));
        if (iVar3 != *(int *)(iVar10 + 0x1c)) {
          pcVar2 = strerror(0);
          uVar11 = 0x24c;
          iVar7 = DAT_000122b8 + 0x120f8;
          iVar10 = DAT_000122bc + 0x12100;
LAB_000120fc:
          IDBG_LINUXAPP_DbgOut(0x82,iVar10,iVar7,uVar11,pcVar2);
          goto LAB_00012064;
        }
        iVar3 = sigwrap_read(__fd,__ptr_00,iVar3);
        iVar5 = *(int *)(iVar10 + 0x1c);
        if (iVar3 != iVar5) {
          pcVar2 = strerror(0);
          uVar11 = 0x254;
          iVar7 = DAT_000122c0 + 0x121d4;
          iVar10 = DAT_000122c4 + 0x121dc;
          goto LAB_000120fc;
        }
        for (iVar3 = 0; iVar3 < iVar5; iVar3 = iVar3 + 1) {
          if (*__ptr != *__ptr_00) {
            __ptr_00 = __ptr_00 + -iVar3;
            __ptr = __ptr + -iVar3;
            IDBG_LINUXAPP_DbgOut(0x86,DAT_000122c8 + 0x12210);
            IDBG_LINUXAPP_DbgOut(0x86,DAT_000122cc + 0x12220);
            goto LAB_00012064;
          }
          __ptr = __ptr + 1;
          __ptr_00 = __ptr_00 + 1;
        }
        __ptr = __ptr + -iVar3;
        __ptr_00 = __ptr_00 + -iVar3;
        if (iVar5 != iVar3) {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_000122d0 + 0x12238,__offset);
          IDBG_LINUXAPP_DbgOut(0x86,DAT_000122d4 + 0x12248);
          uVar6 = 0xffffffff;
          goto LAB_0001224c;
        }
        IDBG_LINUXAPP_DbgOut(0x86,iVar7,uVar12);
        uVar11 = FUN_00012acc(param_3,*(undefined4 *)(iVar10 + 0x1c));
        uVar11 = FUN_00012acc(uVar12 * 100,uVar11);
        *param_4 = uVar11;
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,iVar9,iVar8,0x27d,uVar11);
        __offset = __offset + *(int *)(iVar10 + 0x1c);
      }
      uVar6 = 100;
LAB_0001224c:
      uVar11 = 0;
      *param_4 = uVar6;
LAB_00012068:
      free(__ptr);
      free(__ptr_00);
    }
    sigwrap_close(__fd);
  }
  return uVar11;
}

