
undefined4 FUN_00013494(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  char *pcVar6;
  char cVar7;
  uint uVar8;
  int iVar9;
  
  iVar2 = DAT_00013758;
  iVar3 = DAT_00013754;
  if (param_1 == -1) {
    return 1;
  }
  if (param_2 < *(int *)(DAT_00013754 + 0x10)) {
    iVar9 = *(int *)(DAT_00013758 + param_2 * 4 + 0x10);
    cVar7 = *(char *)(iVar9 + 0x29);
    *(char *)(iVar9 + 0x17) = (char)param_2;
    if (cVar7 == '%') {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00013784,DAT_0001375c,0x178);
      if (*(int *)(iVar3 + 0x10) <= param_2) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00013780,DAT_0001375c,DAT_00013788);
        if (*(int *)(iVar3 + 0x10) <= param_2) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_000137a0,DAT_0001375c,DAT_0001379c);
          return 0;
        }
        iVar3 = *(int *)(iVar2 + param_2 * 4);
        cVar7 = '\0';
        *(undefined1 *)(iVar3 + 0xc) = 0x1d;
        *(undefined1 *)(iVar3 + 0x38) = 0;
        *(undefined1 *)(iVar3 + 0x39) = 0;
        *(undefined1 *)(iVar3 + 0x3a) = 0;
        *(undefined1 *)(iVar3 + 0x3b) = 0;
        *(undefined1 *)(iVar3 + 0x3c) = 0;
        *(undefined1 *)(iVar3 + 0xd) = 0;
        *(undefined1 *)(iVar3 + 0xe) = 0;
        *(undefined1 *)(iVar3 + 0xf) = 0;
        *(undefined1 *)(iVar3 + 0x35) = 1;
        *(undefined1 *)(iVar3 + 0x36) = 5;
        *(undefined1 *)(iVar3 + 0x37) = 0x26;
        *(undefined1 *)(iVar3 + 0x13) = 0x80;
        pcVar6 = (char *)(iVar3 + -1);
        do {
          pcVar6 = pcVar6 + 1;
          cVar7 = cVar7 + *pcVar6;
        } while ((char *)(iVar3 + 0x1f) != pcVar6);
        *(char *)(iVar3 + 0xb) = -cVar7;
        return 0;
      }
      cVar7 = *(char *)(iVar9 + 0x29);
    }
    if (cVar7 == '(') {
      uVar8 = (uint)(*(ushort *)(iVar9 + 0x30) >> 8) | (*(ushort *)(iVar9 + 0x30) & 0xff) << 8;
      uVar1 = ((uint)*(byte *)(iVar9 + 0x21) << 8 | (uint)*(byte *)(iVar9 + 0x22) << 0x10 |
              (uint)*(byte *)(iVar9 + 0x23) << 0x18) >> 0xb;
      if (uVar1 != uVar8) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_0001376c,DAT_0001375c,DAT_00013768,uVar1,uVar8);
        uVar5 = DAT_00013770 & uVar1 << 8;
        *(char *)(iVar9 + 0x30) = (char)(uVar1 >> 8);
        uVar8 = (uVar5 & 0xffff) >> 8 | uVar1 & 0xff00;
        *(char *)(iVar9 + 0x31) = (char)(uVar5 >> 8);
      }
      if (0x40 < uVar8) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00013774,DAT_0001375c,DAT_00013778,uVar8,0x40);
        *(undefined1 *)(iVar9 + 0x31) = 0x40;
        *(undefined1 *)(iVar9 + 0x30) = 0;
      }
      cVar7 = *(char *)(iVar9 + 0x29);
    }
    iVar3 = *(int *)(iVar9 + 0xc);
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00013764,DAT_0001375c,DAT_00013760,cVar7);
    iVar3 = sigwrap_send(param_1,iVar9,iVar3 + 0x20,0);
    if (iVar3 < 1) {
      IDBG_LINUXAPP_DbgOut(0x84,DAT_00013790,DAT_0001375c,DAT_0001378c);
      iVar3 = FUN_000133cc(param_2);
      if (iVar3 == 0) {
        return 1;
      }
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00013798,DAT_0001375c,DAT_00013794);
      uVar4 = 1;
    }
    else {
      uVar4 = 0;
    }
    return uVar4;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013780,DAT_0001375c,DAT_0001377c);
  return 1;
}

