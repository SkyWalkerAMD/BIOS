
undefined4
flash_bios_image(undefined4 param_1,char *param_2,int param_3,undefined4 param_4,undefined4 *param_5
                )

{
  FILE *__stream;
  void *__ptr;
  int iVar1;
  size_t sVar2;
  uint uVar3;
  size_t __n;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  
  iVar6 = DAT_00011eec + 0x11d2c;
  __stream = fopen(param_2,(char *)(DAT_00011ee8 + 0x11d18));
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011ef4 + 0x11d54,DAT_00011ef0 + 0x11d4c,0x1e5,param_2);
  }
  else {
    iVar6 = *(int *)(iVar6 + DAT_00011ef8);
    __ptr = malloc(*(size_t *)(iVar6 + 0x1c));
    if (__ptr != (void *)0x0) {
      uVar7 = 0;
      iVar8 = DAT_00011f1c + 0x11ee4;
      iVar9 = (int)&DAT_00011ee8 + DAT_00011f20;
      do {
        uVar3 = FUN_00012acc(param_4,*(undefined4 *)(iVar6 + 0x1c));
        if (uVar3 <= uVar7) {
          uVar5 = 0;
LAB_00011de0:
          free(__ptr);
          fclose(__stream);
          return uVar5;
        }
        iVar1 = fseek(__stream,param_3,0);
        if (iVar1 != 0) {
          uVar4 = 0x1f6;
          iVar8 = DAT_00011f04 + 0x11dd4;
          iVar6 = DAT_00011f08 + 0x11dd8;
LAB_00011dd4:
          uVar5 = 0xffffffff;
          IDBG_LINUXAPP_DbgOut(0x82,iVar6,iVar8,uVar4);
          goto LAB_00011de0;
        }
        __n = *(size_t *)(iVar6 + 0x1c);
        sVar2 = fread(__ptr,1,__n,__stream);
        if (__n != sVar2) {
          uVar4 = 0x1fc;
          iVar8 = DAT_00011f0c + 0x11e2c;
          iVar6 = DAT_00011f10 + 0x11e30;
          goto LAB_00011dd4;
        }
        iVar1 = spi_write_erase_block(param_1,__ptr,param_3);
        if (iVar1 != 0) {
          uVar4 = 0x203;
          iVar8 = DAT_00011f14 + 0x11e5c;
          iVar6 = DAT_00011f18 + 0x11e60;
          goto LAB_00011dd4;
        }
        iVar1 = uVar7 * 100;
        uVar7 = uVar7 + 1;
        uVar4 = FUN_00012acc(param_4,*(undefined4 *)(iVar6 + 0x1c));
        uVar4 = FUN_00012acc(iVar1,uVar4);
        *param_5 = uVar4;
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,iVar9,iVar8,0x209,uVar4);
        param_3 = param_3 + *(int *)(iVar6 + 0x1c);
      } while( true );
    }
    fclose(__stream);
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011f00 + 0x11da4,DAT_00011efc + 0x11d9c,0x1ed);
  }
  return 0xffffffff;
}

