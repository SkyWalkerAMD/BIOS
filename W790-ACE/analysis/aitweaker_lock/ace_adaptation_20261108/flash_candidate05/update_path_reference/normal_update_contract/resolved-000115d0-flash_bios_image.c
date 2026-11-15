

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
  
  __stream = fopen(param_2,"r");
  iVar2 = &g_coremacros;
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,"[%s:%d]Error while opening %s","hosthelper.c",0x155,param_2);
    uVar7 = 0xffffffff;
  }
  else {
    __size = *(size_t *)(&g_coremacros + 0x1c);
    __ptr = malloc(__size);
    if (__ptr == (void *)0x0) {
      fclose(__stream);
      IDBG_LINUXAPP_DbgOut(0x82,"[%s:%d]Error in allocating the memory","hosthelper.c",0x15d);
      uVar7 = 0xffffffff;
    }
    else {
      if (__size <= param_4) {
        uVar8 = 0;
        do {
          sVar6 = fread(__ptr,1,__size,__stream);
          if (sVar6 != __size) {
            IDBG_LINUXAPP_DbgOut(0x82,"[%s:%d]Error while reading the data from BIOS Recovery file","hosthelper.c",0x16d);
            uVar7 = 0xffffffff;
            goto LAB_000116d4;
          }
          iVar3 = spi_write_erase_block(param_1,__ptr,param_3);
          iVar1 = uVar8 * 100;
          uVar8 = uVar8 + 1;
          if (iVar3 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,"[%s:%d]Error while writing the BIOS SPI Device","hosthelper.c",0x174);
            uVar7 = 0xffffffff;
            goto LAB_000116d4;
          }
          uVar7 = FUN_00011dac(param_4,*(undefined4 *)(iVar2 + 0x1c));
          uVar4 = FUN_00011dac(iVar1,uVar7);
          uVar7 = 0x17a;
          *param_5 = uVar4;
          IDBG_LINUXAPP_Runtime_DbgOut(0x87,"[%s:%d]Flashing progress %d","hosthelper.c",uVar7,uVar4);
          __size = *(size_t *)(iVar2 + 0x1c);
          uVar5 = FUN_00011dac(param_4,__size);
          param_3 = param_3 + __size;
        } while (uVar8 < uVar5);
      }
      uVar7 = 0;
LAB_000116d4:
      free(__ptr);
      fclose(__stream);
    }
  }
  return uVar7;
}

