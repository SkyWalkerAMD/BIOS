
undefined4 LoadPublicKey(void)

{
  int __fd;
  void *__s;
  __off_t _Var1;
  int iVar2;
  int iVar3;
  FILE *__s_00;
  int *piVar4;
  int __offset;
  size_t sVar5;
  int iVar6;
  undefined4 uVar7;
  size_t local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined2 local_24;
  
  uVar7 = DAT_00017a5c;
  local_2c = 0;
  local_30 = 0;
  local_28 = 0;
  local_24 = 0;
  __fd = sigwrap_open(DAT_00017a5c,0);
  iVar3 = DAT_00017a60;
  if (__fd < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017a90,DAT_00017a7c,DAT_00017a8c,uVar7);
    sigwrap_close(__fd);
    uVar7 = 0xffffffff;
  }
  else {
    sVar5 = *(size_t *)(DAT_00017a60 + 0x1c);
    __s = malloc(sVar5);
    if (__s == (void *)0x0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017a98,DAT_00017a7c,DAT_00017a94);
      if (__fd != 0) {
        sigwrap_close(__fd);
      }
LAB_000179d0:
      uVar7 = 0xffffffff;
    }
    else {
      iVar6 = *(int *)(iVar3 + 0x14);
      if (*(int *)(DAT_00017a64 + 0xc) == 1) {
        iVar6 = iVar6 << 1;
      }
      if (0 < iVar6) {
        __offset = 0;
        do {
          memset(__s,0,sVar5);
          _Var1 = lseek(__fd,__offset,0);
          if ((_Var1 == -1) ||
             (iVar2 = sigwrap_read(__fd,__s,*(undefined4 *)(iVar3 + 0x1c)),
             iVar2 != *(int *)(iVar3 + 0x1c))) {
joined_r0x00017a04:
            if (__fd == 0) {
              uVar7 = 0xffffffff;
              goto LAB_00017990;
            }
            sigwrap_close(__fd);
            free(__s);
            goto LAB_000179d0;
          }
          iVar2 = ScanforFMH(__s,iVar2);
          if ((iVar2 != 0) && (*(short *)(iVar2 + 0x22) == 2)) {
            iVar6 = *(int *)(iVar3 + 0x1c);
            memcpy(&local_2c,(void *)((int)__s + iVar6 + -0x2000),10);
            iVar3 = strcmp((char *)&local_2c,DAT_00017a68);
            if (iVar3 == 0) {
              memcpy(&local_30,(void *)((int)__s + iVar6 + -0x1ff6),4);
              sVar5 = local_30;
              if ((int)local_30 < 0x321) {
                __s_00 = fopen(DAT_00017a70,DAT_00017a6c);
                if (__s_00 != (FILE *)0x0) {
                  fwrite((void *)((int)__s + iVar6 + -0x1ff2),1,sVar5,__s_00);
                  if (__fd != 0) {
                    sigwrap_close(__fd);
                  }
                  free(__s);
                  fclose(__s_00);
                  return 0;
                }
                piVar4 = __errno_location();
                IDBG_LINUXAPP_DbgOut(0x82,DAT_00017a78,DAT_00017a7c,DAT_00017a74,*piVar4);
              }
              else {
                IDBG_LINUXAPP_DbgOut(0x86,DAT_00017a88,local_30);
              }
            }
            else {
              IDBG_LINUXAPP_DbgOut(0x82,DAT_00017a84,DAT_00017a7c,DAT_00017a80);
            }
            goto joined_r0x00017a04;
          }
          sVar5 = *(size_t *)(iVar3 + 0x1c);
          __offset = __offset + sVar5;
        } while (__offset < iVar6);
      }
      if (__fd == 0) {
        uVar7 = 0;
LAB_00017990:
        free(__s);
        return uVar7;
      }
      sigwrap_close(__fd);
      free(__s);
      uVar7 = 0;
    }
  }
  return uVar7;
}

