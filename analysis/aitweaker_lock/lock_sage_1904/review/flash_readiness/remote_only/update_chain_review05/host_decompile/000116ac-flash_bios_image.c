
undefined4
flash_bios_image(undefined4 param_1,char *param_2,int param_3,uint param_4,undefined4 *param_5)

{
  int iVar1;
  int iVar2;
  FILE *__stream;
  void *__ptr;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  size_t sVar6;
  size_t __size;
  undefined4 uVar7;
  uint uVar8;
  
  __stream = fopen(param_2,DAT_00011834);
  iVar2 = DAT_00011838;
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011858,DAT_00011844,DAT_00011854,param_2);
    uVar7 = 0xffffffff;
  }
  else {
    __size = *(size_t *)(DAT_00011838 + 0x1c);
    __ptr = malloc(__size);
    if (__ptr == (void *)0x0) {
      fclose(__stream);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011860,DAT_00011844,DAT_0001185c);
      uVar7 = 0xffffffff;
    }
    else {
      if (__size <= param_4) {
        uVar8 = 0;
        do {
          sVar6 = fread(__ptr,1,__size,__stream);
          if (sVar6 != __size) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_0001184c,DAT_00011844,DAT_00011848);
            uVar7 = 0xffffffff;
            goto LAB_000117b0;
          }
          iVar3 = spi_write_erase_block(param_1,__ptr,param_3);
          iVar1 = uVar8 * 100;
          uVar8 = uVar8 + 1;
          if (iVar3 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00011850,DAT_00011844,0x154);
            uVar7 = 0xffffffff;
            goto LAB_000117b0;
          }
          uVar7 = FUN_0001226c(param_4,*(undefined4 *)(iVar2 + 0x1c));
          uVar4 = FUN_0001226c(iVar1,uVar7);
          uVar7 = DAT_0001183c;
          *param_5 = uVar4;
          IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011840,DAT_00011844,uVar7,uVar4);
          __size = *(size_t *)(iVar2 + 0x1c);
          uVar5 = FUN_0001226c(param_4,__size);
          param_3 = param_3 + __size;
        } while (uVar8 < uVar5);
      }
      uVar7 = 0;
LAB_000117b0:
      free(__ptr);
      fclose(__stream);
    }
  }
  return uVar7;
}

