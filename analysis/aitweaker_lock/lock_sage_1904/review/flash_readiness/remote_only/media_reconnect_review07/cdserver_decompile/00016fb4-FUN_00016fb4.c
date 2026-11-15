
undefined4 FUN_00016fb4(int param_1)

{
  char *__format;
  char *__format_00;
  int iVar1;
  char *__s;
  int iVar2;
  int iVar3;
  int *piVar4;
  char *pcVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  char *__s_00;
  
  iVar1 = FUN_00018d5c(DAT_000173a8);
  if (iVar1 == 0) {
    safe_system(DAT_0001740c);
  }
  safe_system(DAT_000173ac);
  safe_system(DAT_000173b0);
  safe_system(DAT_000173b4);
  safe_system(DAT_000173b8);
  safe_system(DAT_000173bc);
  safe_system(DAT_000173c0);
  safe_system(DAT_000173c4);
  safe_system(DAT_000173c8);
  safe_system(DAT_000173cc);
  safe_system(DAT_000173d0);
  safe_system(DAT_000173d4);
  safe_system(DAT_000173d8);
  __s = malloc(0x800);
  uVar6 = DAT_000173e8;
  __format_00 = DAT_000173e4;
  __format = DAT_000173e0;
  pcVar5 = DAT_000173dc;
  if (__s == (char *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017440,DAT_00017400,0xbb);
    uVar6 = 0xffffffea;
  }
  else if (param_1 < 5) {
    if (param_1 < 1) {
LAB_00017200:
      free(__s);
      safe_system(DAT_00017408);
      uVar6 = 0;
    }
    else {
      iVar1 = 0;
      while( true ) {
        memset(__s,0,0x400);
        snprintf(__s,0x400,pcVar5,iVar1);
        iVar2 = safe_system(__s);
        __s_00 = __s + 0x400;
        if (iVar2 < 0) {
          piVar4 = __errno_location();
          iVar2 = *piVar4;
          pcVar5 = strerror(iVar2);
          uVar7 = 0xfe;
          uVar6 = DAT_00017410;
          goto LAB_00017250;
        }
        memset(__s,0,0x400);
        snprintf(__s,0x400,__format,iVar1);
        iVar2 = safe_system(__s);
        if (iVar2 < 0) break;
        memset(__s,0,0x400);
        snprintf(__s,0x400,__format_00,iVar1);
        iVar2 = safe_system(__s);
        if (iVar2 < 0) {
          piVar4 = __errno_location();
          iVar2 = *piVar4;
          pcVar5 = strerror(iVar2);
          uVar6 = DAT_00017424;
          uVar7 = DAT_00017420;
          goto LAB_00017250;
        }
        memset(__s,0,0x400);
        snprintf(__s,0x400,DAT_000173ec,iVar1);
        iVar2 = safe_system(__s);
        if (iVar2 < 0) {
          piVar4 = __errno_location();
          iVar2 = *piVar4;
          pcVar5 = strerror(iVar2);
          uVar6 = DAT_0001742c;
          uVar7 = DAT_00017428;
          goto LAB_00017250;
        }
        memset(__s,0,0x400);
        memset(__s_00,0,0x1d);
        FUN_000178c4(__s_00,DAT_000173f4,uVar6,iVar1,DAT_000173f0);
        iVar2 = iVar1;
        iVar3 = snprintf(__s,0x400,DAT_000173f8,__s_00,iVar1);
        uVar7 = DAT_00017434;
        uVar8 = DAT_00017430;
        if (0x3ff < iVar3) goto LAB_00017334;
        iVar3 = safe_system(__s);
        if (iVar3 < 0) {
          piVar4 = __errno_location();
          iVar2 = *piVar4;
          pcVar5 = strerror(iVar2);
          uVar6 = DAT_00017438;
          uVar7 = 400;
          goto LAB_00017250;
        }
        iVar1 = iVar1 + 1;
        if (param_1 == iVar1) goto LAB_00017200;
        snprintf(__s,0x400,DAT_000173fc,iVar1,iVar2);
        iVar2 = safe_system(__s);
        if (iVar2 < 0) {
          piVar4 = __errno_location();
          iVar2 = *piVar4;
          pcVar5 = strerror(iVar2);
          uVar6 = DAT_00017404;
          uVar7 = 0xdf;
LAB_00017250:
          IDBG_LINUXAPP_DbgOut(0x82,uVar6,DAT_00017400,uVar7,iVar1,iVar2,pcVar5);
          free(__s);
          return 0xffffffea;
        }
      }
      piVar4 = __errno_location();
      iVar3 = *piVar4;
      pcVar5 = strerror(iVar3);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017418,DAT_00017400,DAT_00017414,iVar1,iVar3,pcVar5);
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_0001741c,DAT_00017400,0x11c,iVar1,__s,iVar2);
      free(__s);
      uVar6 = 0xffffffea;
    }
  }
  else {
    uVar7 = DAT_0001743c;
    uVar8 = 0xc1;
    iVar1 = param_1;
LAB_00017334:
    IDBG_LINUXAPP_DbgOut(0x82,uVar7,DAT_00017400,uVar8,iVar1);
    free(__s);
    uVar6 = 0xffffffea;
  }
  return uVar6;
}

