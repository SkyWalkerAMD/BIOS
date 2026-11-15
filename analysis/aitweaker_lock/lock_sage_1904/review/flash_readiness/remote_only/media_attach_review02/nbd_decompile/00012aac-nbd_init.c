
undefined4 nbd_init(undefined1 *param_1)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  char *pcVar6;
  uint uVar7;
  int iVar8;
  undefined4 uVar9;
  undefined4 *puVar10;
  pthread_t local_8c;
  pthread_t pStack_88;
  void *local_84;
  stat64 sStack_80;
  
  puVar2 = DAT_00012f38;
  param_1[0x14] = 0xff;
  param_1[0x15] = 0xff;
  param_1[0x16] = 0xff;
  param_1[0x17] = 0xff;
  param_1[0x38] = 0;
  param_1[0x39] = 0;
  param_1[0x3a] = 0;
  param_1[0x3b] = 0;
  param_1[0x3c] = 0;
  param_1[0x3d] = 0;
  param_1[0x3e] = 0;
  param_1[0x3f] = 0;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[0x30] = 0;
  param_1[0x31] = 0;
  param_1[0x32] = 0;
  param_1[0x33] = 0;
  param_1[0x34] = 0;
  param_1[0x35] = 0;
  param_1[0x36] = 0;
  param_1[0x37] = 0;
  param_1[0x40] = 0;
  param_1[0x41] = 0;
  param_1[0x42] = 0;
  param_1[0x43] = 0;
  param_1[0x28] = 0;
  param_1[0x29] = 0;
  param_1[0x2a] = 0;
  param_1[0x2b] = 0;
  pcVar6 = DAT_00012f40;
  puVar10 = DAT_00012f3c;
  iVar8 = 0;
  param_1[0x2c] = 0;
  param_1[0x2d] = 0;
  param_1[0x2e] = 0;
  param_1[0x2f] = 0;
  *puVar2 = 0;
  while (iVar3 = __xstat64(3,pcVar6,&sStack_80), iVar3 == 0) {
    iVar8 = iVar8 + 1;
    if (iVar8 == 8) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00012f48,DAT_00012f44,200);
      goto LAB_00012ba0;
    }
    puVar10 = puVar10 + 1;
    pcVar6 = (char *)*puVar10;
  }
  if ((*puVar2 & 1) != 0) {
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00012f60,DAT_00012f44,0xc3,iVar8);
  }
  uVar1 = *(uint *)(param_1 + 0x18);
  uVar7 = (*(int *)(param_1 + 0x1c) << 4 | uVar1 >> 0x1c) -
          (*(int *)(param_1 + 0x1c) + (uint)(uVar1 * 0x10 < uVar1));
  param_1[0x16] = (char)((uint)iVar8 >> 0x10);
  param_1[0x17] = (char)((uint)iVar8 >> 0x18);
  param_1[0x14] = (char)iVar8;
  param_1[0x15] = (char)((uint)iVar8 >> 8);
  iVar8 = FUN_00011a3c(param_1,0,uVar1 * 0x3c >> 10 | (uVar7 * 4 | uVar1 * 0xf >> 0x1e) << 0x16,
                       (uVar7 & 0x3fffffff) >> 8);
  if (iVar8 == 0) {
    iVar3 = FUN_00011a3c(param_1,1,0x2800,0);
    iVar8 = DAT_00012f4c;
    if (iVar3 == 0) {
      iVar3 = open64(*(char **)(DAT_00012f4c + *(int *)(param_1 + 0x14) * 4),2);
      param_1[0x10] = (char)iVar3;
      param_1[0x11] = (char)((uint)iVar3 >> 8);
      param_1[0x12] = (char)((uint)iVar3 >> 0x10);
      param_1[0x13] = (char)((uint)iVar3 >> 0x18);
      if (-1 < iVar3) {
        pthread_create(&local_8c,(pthread_attr_t *)0x0,DAT_00012f50,param_1);
        sleep(1);
        pthread_create(&pStack_88,(pthread_attr_t *)0x0,DAT_00012f54,param_1);
        pthread_join(local_8c,&local_84);
        sleep(1);
        iVar3 = DAT_00012f58;
        iVar4 = __xstat64(3,*(char **)(DAT_00012f58 + *(int *)(param_1 + 0x14) * 4 + 0x20),
                          &sStack_80);
        if (iVar4 != 0) {
          sleep(1);
          iVar3 = __xstat64(3,*(char **)(iVar3 + *(int *)(param_1 + 0x14) * 4 + 0x20),&sStack_80);
          if (iVar3 != 0) {
            sleep(1);
          }
        }
        close(*(int *)(param_1 + 0x10));
        iVar3 = open64(*(char **)(iVar8 + *(int *)(param_1 + 0x14) * 4),2);
        param_1[0x10] = (char)iVar3;
        param_1[0x11] = (char)((uint)iVar3 >> 8);
        param_1[0x12] = (char)((uint)iVar3 >> 0x10);
        param_1[0x13] = (char)((uint)iVar3 >> 0x18);
        if (-1 < iVar3) {
          return local_84;
        }
        uVar9 = *(undefined4 *)(iVar8 + *(int *)(param_1 + 0x14) * 4);
        piVar5 = __errno_location();
        iVar8 = *piVar5;
        pcVar6 = strerror(iVar8);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00012f5c,DAT_00012f44,0x2f8,uVar9,iVar8,pcVar6);
        FUN_00011ca0(param_1);
        goto LAB_00012ba0;
      }
      uVar9 = *(undefined4 *)(iVar8 + *(int *)(param_1 + 0x14) * 4);
      piVar5 = __errno_location();
      iVar8 = *piVar5;
      pcVar6 = strerror(iVar8);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00012f70,DAT_00012f44,DAT_00012f6c,uVar9,iVar8,pcVar6);
    }
    else if ((*puVar2 & 2) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00012f68,DAT_00012f44,DAT_00012f64);
    }
  }
  else if ((*puVar2 & 2) != 0) {
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00012f78,DAT_00012f44,DAT_00012f74);
  }
  FUN_00011bf8(*(undefined4 *)(param_1 + 0x14));
LAB_00012ba0:
  param_1[0x14] = 0xff;
  param_1[0x15] = 0xff;
  param_1[0x16] = 0xff;
  param_1[0x17] = 0xff;
  return 0xffffffff;
}

