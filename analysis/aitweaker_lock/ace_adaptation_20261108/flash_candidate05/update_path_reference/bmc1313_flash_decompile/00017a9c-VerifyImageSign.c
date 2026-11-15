
undefined4 VerifyImageSign(uint param_1,int param_2,int param_3)

{
  int iVar1;
  void *__dest;
  int iVar2;
  int iVar3;
  __off_t _Var4;
  size_t sVar5;
  size_t __size;
  undefined4 uVar6;
  uint __size_00;
  int iVar7;
  int local_68;
  undefined4 local_64;
  undefined1 auStack_60 [68];
  
  memset(auStack_60,0,0x40);
  if (1 < param_1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f30,DAT_00017f20,0xc30);
    return 0xffffffff;
  }
  iVar1 = LoadPublicKey();
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f48,DAT_00017f20,DAT_00017f44);
    return 0xffffffff;
  }
  if (param_1 == 0) {
    memcpy(&local_68,(void *)(param_2 + param_3 + -8),8);
    if (local_68 != DAT_00017f0c) {
      __dest = malloc(0x80);
      if (__dest == (void *)0x0) {
        return 0xffffffff;
      }
      memcpy(__dest,(void *)(param_2 + param_3 + -0x88),0x80);
      uVar6 = 0xffffffff;
      goto LAB_00017be0;
    }
    __size_00 = ~(local_64 | 0xff000000);
    __dest = malloc(__size_00);
    iVar7 = __size_00 + 8;
    if (__dest == (void *)0x0) {
      return 0xffffffff;
    }
    memcpy(__dest,(void *)(param_2 + (param_3 - iVar7)),__size_00);
    if (6 < local_64._3_1_) {
      uVar6 = 0xffffffff;
      goto LAB_00017be0;
    }
    uVar6 = *(undefined4 *)(DAT_00017f10 + (uint)local_64._3_1_ * 4 + 0x48);
    iVar2 = GenerateDigestMultiPartFromMem(uVar6,auStack_60,0x40,param_2,param_3 - iVar7);
    if (iVar2 < 1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f24,DAT_00017f20,DAT_00017f68);
      uVar6 = 0xffffffff;
      goto LAB_00017be0;
    }
    iVar1 = -1;
LAB_00017b8c:
    iVar3 = access(DAT_00017f14,0);
    if (iVar3 == 0) {
      iVar7 = VerifySignatureWithDigest(DAT_00017f14,__dest,iVar7 + -8,auStack_60,iVar2,uVar6);
      if (iVar7 == 1) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00017f18);
        uVar6 = 0;
      }
      else {
        uVar6 = 0xffffffff;
      }
    }
    else {
      puts(DAT_00017f34);
      uVar6 = 0xffffffff;
    }
    if (iVar1 == -1) goto LAB_00017be0;
LAB_00017bd8:
    sigwrap_close(iVar1);
  }
  else {
    iVar1 = sigwrap_open(param_2,0);
    if (iVar1 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f64,DAT_00017f20,DAT_00017f60);
      return 0xffffffff;
    }
    _Var4 = lseek(iVar1,0,2);
    if (_Var4 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f54,DAT_00017f20,0xc60);
      sigwrap_close(iVar1);
      return 0xffffffff;
    }
    _Var4 = lseek(iVar1,-8,1);
    if (_Var4 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f70,DAT_00017f20,DAT_00017f6c);
      sigwrap_close(iVar1);
      return 0xffffffff;
    }
    iVar7 = sigwrap_read(iVar1,&local_68,8);
    if (iVar7 != 8) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f3c,DAT_00017f20,DAT_00017f4c);
      sigwrap_close(iVar1);
      return 0xffffffff;
    }
    if (local_68 == DAT_00017f0c) {
      __size = ~(local_64 | 0xff000000);
      iVar7 = __size + 8;
    }
    else {
      __size = 0x80;
      iVar7 = 0x88;
    }
    __dest = malloc(__size);
    if (__dest == (void *)0x0) {
      sigwrap_close(iVar1);
      return 0xffffffff;
    }
    _Var4 = lseek(iVar1,0,2);
    if (_Var4 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f54,DAT_00017f20,DAT_00017f50);
    }
    else {
      _Var4 = lseek(iVar1,-iVar7,1);
      if (_Var4 == -1) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f5c,DAT_00017f20,DAT_00017f58);
      }
      else {
        sVar5 = sigwrap_read(iVar1,__dest,__size);
        if (__size == sVar5) {
          iVar2 = sigwrap_read(iVar1,&local_68,8);
          if (iVar2 == 8) {
            _Var4 = lseek(iVar1,0,0);
            if (_Var4 == -1) {
              IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f2c,DAT_00017f20,DAT_00017f28);
            }
            else if (local_68 == DAT_00017f0c) {
              if (local_64._3_1_ < 7) {
                uVar6 = *(undefined4 *)(DAT_00017f10 + (uint)local_64._3_1_ * 4 + 0x48);
                iVar2 = GenerateDigestMultiPartFromFile(iVar1,uVar6,auStack_60,0x40);
                if (0 < iVar2) goto LAB_00017b8c;
                IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f24,DAT_00017f20,DAT_00017f1c);
                uVar6 = 0xffffffff;
              }
              else {
                uVar6 = 0xffffffff;
              }
              goto LAB_00017bd8;
            }
          }
          else {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f3c,DAT_00017f20,DAT_00017f40);
          }
        }
        else {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00017f3c,DAT_00017f20,DAT_00017f38);
        }
      }
    }
    sigwrap_close(iVar1);
    uVar6 = 0xffffffff;
  }
LAB_00017be0:
  free(__dest);
  return uVar6;
}

