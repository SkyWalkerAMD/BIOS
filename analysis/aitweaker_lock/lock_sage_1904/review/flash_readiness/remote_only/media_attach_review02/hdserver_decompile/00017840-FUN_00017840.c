
undefined4 FUN_00017840(int param_1)

{
  undefined4 *puVar1;
  char *__format;
  char *__s;
  int iVar2;
  int iVar3;
  int *piVar4;
  char *pcVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int iVar8;
  char *__s_00;
  
  safe_system(DAT_00017c28);
  safe_system(DAT_00017c2c);
  safe_system(DAT_00017c30);
  safe_system(DAT_00017c34);
  safe_system(DAT_00017c38);
  safe_system(DAT_00017c3c);
  safe_system(DAT_00017c40);
  safe_system(DAT_00017c44);
  safe_system(DAT_00017c48);
  safe_system(DAT_00017c4c);
  safe_system(DAT_00017c50);
  safe_system(DAT_00017c54);
  safe_system(DAT_00017c58);
  __s = malloc(0x800);
  uVar6 = DAT_00017c68;
  __format = DAT_00017c64;
  pcVar5 = DAT_00017c60;
  puVar1 = DAT_00017c5c;
  if (__s == (char *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017cc0,DAT_00017c84,0xd9);
    uVar6 = 0xffffffea;
  }
  else if (param_1 < 5) {
    if (param_1 < 1) {
LAB_00017a8c:
      free(__s);
      safe_system(DAT_00017c8c);
      uVar6 = 0;
    }
    else {
      iVar8 = 0;
      while( true ) {
        memset(__s,0,0x400);
        iVar3 = iVar8;
        snprintf(__s,0x400,pcVar5,*puVar1,iVar8);
        iVar2 = safe_system(__s);
        __s_00 = __s + 0x400;
        if (iVar2 < 0) {
          piVar4 = __errno_location();
          iVar3 = *piVar4;
          pcVar5 = strerror(iVar3);
          uVar7 = 0x11c;
          uVar6 = DAT_00017c90;
          goto LAB_00017ad0;
        }
        memset(__s,0,0x400);
        snprintf(__s,0x400,__format,iVar8,iVar3);
        iVar3 = safe_system(__s);
        if (iVar3 < 0) break;
        memset(__s,0,0x400);
        iVar3 = iVar8;
        snprintf(__s,0x400,DAT_00017c6c,puVar1[1],iVar8);
        iVar2 = safe_system(__s);
        if (iVar2 < 0) {
          piVar4 = __errno_location();
          iVar3 = *piVar4;
          pcVar5 = strerror(iVar3);
          uVar6 = DAT_00017ca8;
          uVar7 = DAT_00017ca4;
          goto LAB_00017ad0;
        }
        memset(__s,0,0x400);
        snprintf(__s,0x400,DAT_00017c70,iVar8,iVar3);
        iVar3 = safe_system(__s);
        if (iVar3 < 0) {
          piVar4 = __errno_location();
          iVar3 = *piVar4;
          pcVar5 = strerror(iVar3);
          uVar7 = 0x174;
          uVar6 = DAT_00017cac;
          goto LAB_00017ad0;
        }
        memset(__s,0,0x400);
        memset(__s_00,0,0x400);
        FUN_00018204(__s_00,DAT_00017c78,uVar6,iVar8,DAT_00017c74);
        iVar3 = iVar8;
        iVar2 = snprintf(__s,0x400,DAT_00017c7c,__s_00,iVar8);
        if (0x3ff < iVar2) {
          uVar7 = 0x19c;
          uVar6 = DAT_00017cb0;
          param_1 = iVar8;
          goto LAB_00017bb4;
        }
        iVar2 = safe_system(__s);
        if (iVar2 < 0) {
          piVar4 = __errno_location();
          iVar3 = *piVar4;
          pcVar5 = strerror(iVar3);
          uVar6 = DAT_00017cb8;
          uVar7 = DAT_00017cb4;
          goto LAB_00017ad0;
        }
        iVar8 = iVar8 + 1;
        if (param_1 == iVar8) goto LAB_00017a8c;
        snprintf(__s,0x400,DAT_00017c80,iVar8,iVar3);
        iVar3 = safe_system(__s);
        if (iVar3 < 0) {
          piVar4 = __errno_location();
          iVar3 = *piVar4;
          pcVar5 = strerror(iVar3);
          uVar6 = DAT_00017c88;
          uVar7 = 0xfd;
LAB_00017ad0:
          IDBG_LINUXAPP_DbgOut(0x82,uVar6,DAT_00017c84,uVar7,iVar8,iVar3,pcVar5);
          free(__s);
          return 0xffffffea;
        }
      }
      piVar4 = __errno_location();
      iVar2 = *piVar4;
      pcVar5 = strerror(iVar2);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017c98,DAT_00017c84,DAT_00017c94,iVar8,iVar2,pcVar5);
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00017ca0,DAT_00017c84,DAT_00017c9c,iVar8,__s,iVar3);
      free(__s);
      uVar6 = 0xffffffea;
    }
  }
  else {
    uVar7 = 0xdf;
    uVar6 = DAT_00017cbc;
LAB_00017bb4:
    IDBG_LINUXAPP_DbgOut(0x82,uVar6,DAT_00017c84,uVar7,param_1);
    free(__s);
    uVar6 = 0xffffffea;
  }
  return uVar6;
}

