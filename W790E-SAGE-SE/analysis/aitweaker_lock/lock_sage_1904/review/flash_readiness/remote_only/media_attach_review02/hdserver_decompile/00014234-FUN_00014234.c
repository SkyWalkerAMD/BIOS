
void FUN_00014234(uint param_1,undefined4 param_2)

{
  ushort uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined2 uVar4;
  uint uVar5;
  undefined1 uVar6;
  int iVar7;
  int iVar8;
  void *__arg;
  undefined4 extraout_r3;
  undefined4 extraout_r3_00;
  uint uVar9;
  undefined4 uVar10;
  uint uVar11;
  int iVar12;
  int iVar13;
  bool bVar14;
  bool bVar15;
  ushort local_32 [3];
  pthread_t apStack_2c [2];
  
  iVar2 = DAT_000146ec;
  local_32[0] = (ushort)param_1;
  iVar12 = DAT_000146f0 + param_1 * 0x2003e;
  if ((int)(param_1 & 0xff) < *(int *)(DAT_000146ec + 0x130)) {
    iVar7 = DAT_000146f4 + (param_1 & 0xff) * 9;
    iVar13 = 0x142c4;
    SetAuthInfo(*(undefined4 *)(iVar7 + 0x20),*(undefined4 *)(iVar7 + 0x24),
                *(undefined1 *)(iVar7 + 0x28),iVar12,1);
    *(char *)(iVar12 + 0x17) = (char)param_1;
  }
  else {
    iVar13 = 0x146e8;
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001471c,DAT_000146f8,0xef);
  }
  uVar3 = DAT_000146f8;
  iVar7 = DAT_000146f4;
  __arg = (void *)(uint)local_32[0];
  iVar12 = (int)__arg * 4;
  if (*(int *)(iVar2 + iVar12 + 0x1fc) != 0) {
    bVar15 = true;
    do {
      iVar8 = *(int *)(iVar2 + (int)__arg * 0x4c);
      if (iVar8 == 1) {
        if (bVar15) {
          iVar13 = 0x14600;
          iVar12 = pthread_create(apStack_2c,(pthread_attr_t *)0x0,DAT_0001470c,__arg);
          if (iVar12 != 1) {
            __arg = (void *)(uint)local_32[0];
            goto LAB_000143e0;
          }
          uVar9 = (uint)local_32[0];
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00014714,uVar3,DAT_00014710,uVar9);
          *(undefined1 *)(*(int *)(iVar7 + (uint)local_32[0] * 4 + 0x10) + 0x29) = 0xf7;
          *(undefined4 *)(iVar2 + (uint)local_32[0] * 0x4c) = 0;
          iVar12 = sigwrap_write(param_2,local_32);
          bVar15 = true;
          if (iVar12 != 2) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00014700,uVar3,DAT_00014718,uVar9);
          }
        }
        else {
LAB_000143e0:
          iVar12 = iVar2 + (int)__arg * 0x4c;
          uVar1 = *(ushort *)(iVar12 + 0x44);
          bVar15 = (uVar1 & 1) == 0;
          if (bVar15) {
            iVar8 = *(int *)(iVar7 + (int)__arg * 4 + 0x10);
            iVar13 = iVar8 + 0x3d;
            *(byte *)(iVar8 + 0x3d) = (byte)uVar1 & 1;
          }
          if (bVar15) {
            *(int *)(iVar12 + 0x48) = iVar13;
          }
          iVar13 = nbd_read_req(iVar2 + (int)__arg * 0x4c);
          iVar12 = DAT_00014704;
          if (iVar13 == 0) {
            uVar9 = (uint)local_32[0];
            iVar12 = iVar2 + uVar9 * 0x4c;
            iVar13 = *(int *)(iVar7 + uVar9 * 4 + 0x10);
            if (*(short *)(iVar12 + 0x46) == 1) {
              *(undefined1 *)(iVar13 + 0x29) = 0x2a;
              iVar8 = *(int *)(uVar9 * 0x4c + iVar2 + 0x40);
              iVar12 = iVar8 + 0x1d;
              *(char *)(iVar13 + 0x39) = (char)iVar8;
              *(char *)(iVar13 + 0xc) = (char)iVar12;
              *(char *)(iVar13 + 0xd) = (char)((uint)iVar12 >> 8);
              *(char *)(iVar13 + 0xe) = (char)((uint)iVar12 >> 0x10);
              *(char *)(iVar13 + 0xf) = (char)((uint)iVar12 >> 0x18);
              *(char *)(iVar13 + 0x3a) = (char)((uint)iVar8 >> 8);
              *(char *)(iVar13 + 0x3b) = (char)((uint)iVar8 >> 0x10);
              *(char *)(iVar13 + 0x3c) = (char)((uint)iVar8 >> 0x18);
            }
            else {
              *(undefined1 *)(iVar13 + 0x29) = 0x28;
              uVar10 = *(undefined4 *)(iVar12 + 0x40);
              *(char *)(iVar13 + 0x20) = (char)uVar10;
              *(char *)(iVar13 + 0x21) = (char)((uint)uVar10 >> 8);
              *(char *)(iVar13 + 0x22) = (char)((uint)uVar10 >> 0x10);
              *(char *)(iVar13 + 0x23) = (char)((uint)uVar10 >> 0x18);
            }
            iVar12 = iVar2 + uVar9 * 0x4c;
            bVar15 = *(uint *)(iVar12 + 0x1c) <= *(uint *)(iVar12 + 0x34);
            if (*(uint *)(iVar12 + 0x34) == *(uint *)(iVar12 + 0x1c)) {
              bVar15 = *(uint *)(iVar12 + 0x18) <= *(uint *)(iVar12 + 0x30);
            }
            if (bVar15) {
              uVar5 = FUN_00019700();
            }
            else {
              uVar5 = 0;
            }
            uVar11 = (uVar5 ^ (uVar5 >> 0x10 | uVar5 << 0x10)) >> 8 & 0xffff00ff ^ uVar5 >> 8;
            *(char *)(iVar13 + 0x2c) = (char)(uVar5 >> 0x10);
            *(char *)(iVar13 + 0x2b) = (char)uVar11;
            *(char *)(iVar13 + 0x2d) = (char)(uVar11 >> 0x10);
            *(char *)(iVar13 + 0x2e) = (char)uVar5;
            iVar12 = iVar2 + uVar9 * 0x4c;
            bVar15 = *(int *)(iVar12 + 0x1c) == 0;
            if (*(int *)(iVar12 + 0x1c) == 0) {
              bVar15 = *(uint *)(iVar12 + 0x18) <= *(uint *)(iVar12 + 0x40);
            }
            if (bVar15) {
              uVar4 = FUN_00019700();
            }
            else {
              uVar4 = 1;
            }
            *(char *)(iVar13 + 0x30) = (char)((ushort)uVar4 >> 8);
            *(char *)(iVar13 + 0x31) = (char)uVar4;
            *(undefined4 *)(iVar2 + uVar9 * 0x4c) = 2;
          }
          else {
            uVar9 = (uint)local_32[0];
            if (*(int *)(DAT_00014704 + uVar9 * 4) != -1) {
              FUN_000180b4();
              uVar9 = (uint)local_32[0];
              *(undefined4 *)(iVar12 + uVar9 * 4) = 0xffffffff;
            }
            if (*(int *)(iVar2 + uVar9 * 0x4c + 0x14) != -1) {
              nbd_disconnect(uVar9 * 0x4c + iVar2);
              uVar9 = (uint)local_32[0];
              *(undefined4 *)(uVar9 * 0x4c + iVar2 + 0x14) = 0xffffffff;
            }
            *(undefined1 *)(*(int *)(iVar7 + uVar9 * 4 + 0x10) + 0x29) = 0xf7;
            *(undefined4 *)(iVar2 + uVar9 * 0x4c) = 0;
          }
          iVar12 = sigwrap_write(param_2,local_32,2);
          if (iVar12 != 2) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00014700,uVar3,DAT_00014708);
          }
          bVar15 = false;
        }
        *(undefined4 *)(iVar2 + (uint)local_32[0] * 4 + 0x20c) = 1;
      }
      else if ((0 < iVar8) && (iVar8 - 3U < 3)) {
        bVar14 = iVar8 == 5;
        if (bVar14) {
          iVar8 = 0x1a;
        }
        iVar12 = *(int *)(iVar7 + iVar12 + 0x10);
        if (bVar14) {
          *(char *)(iVar12 + 0x29) = (char)iVar8;
        }
        else {
          if (iVar8 == 3) {
            uVar6 = 0;
          }
          else {
            uVar6 = 0x25;
          }
          *(undefined1 *)(iVar12 + 0x29) = uVar6;
        }
        iVar12 = sigwrap_write(param_2,local_32,2);
        uVar10 = extraout_r3;
        if (iVar12 != 2) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00014700,uVar3,DAT_000146fc);
          uVar10 = extraout_r3_00;
        }
        uVar9 = (uint)local_32[0];
        iVar12 = *(int *)(iVar2 + uVar9 * 0x4c);
        if (iVar12 == 3) {
          uVar10 = 5;
        }
        *(undefined4 *)(iVar2 + uVar9 * 4 + 0x20c) = 1;
        if (iVar12 == 3) {
          *(undefined4 *)(iVar2 + uVar9 * 0x4c) = uVar10;
        }
        else if (iVar12 == 5) {
          *(undefined4 *)(iVar2 + uVar9 * 0x4c) = 4;
        }
        else {
          *(undefined4 *)(iVar2 + uVar9 * 0x4c) = 0;
        }
      }
      iVar13 = 0x143ac;
      select_sleep(0,1);
      __arg = (void *)(uint)local_32[0];
      iVar12 = (int)__arg * 4;
    } while (*(int *)(iVar2 + iVar12 + 0x1fc) != 0);
  }
  return;
}

