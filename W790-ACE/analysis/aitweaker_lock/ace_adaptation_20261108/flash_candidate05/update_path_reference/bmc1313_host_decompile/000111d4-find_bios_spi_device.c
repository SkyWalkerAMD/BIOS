
undefined4 find_bios_spi_device(char *param_1)

{
  char *__needle;
  char *__delim;
  FILE *__stream;
  char *pcVar1;
  size_t sVar2;
  long lVar3;
  undefined4 uVar4;
  char local_74 [88];
  
  pcVar1 = DAT_00011334;
  local_74[0] = '\0';
  local_74[1] = '\0';
  local_74[2] = '\0';
  local_74[3] = '\0';
  if (param_1 == (char *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011358,DAT_00011348,0xbe,DAT_00011354);
    uVar4 = 0xffffffff;
  }
  else {
    __stream = fopen(DAT_00011334,DAT_00011338);
    __delim = DAT_00011340;
    __needle = DAT_0001133c;
    if (__stream == (FILE *)0x0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001135c,DAT_00011348,200,pcVar1);
      uVar4 = 0xffffffff;
    }
    else {
      lVar3 = -1;
      while (pcVar1 = fgets(local_74 + 4,0x50,__stream), pcVar1 != (char *)0x0) {
        pcVar1 = strstr(local_74 + 4,__needle);
        if (pcVar1 != (char *)0x0) {
          pcVar1 = strtok(local_74 + 4,__delim);
          if (pcVar1 == (char *)0x0) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_0001134c,DAT_00011348,0xd3);
            fclose(__stream);
            return 0xffffffff;
          }
          sVar2 = strlen(pcVar1);
          memcpy(local_74,pcVar1 + 3,sVar2 - 3);
          lVar3 = strtol(local_74,(char **)0x0,10);
        }
      }
      fclose(__stream);
      if (lVar3 == -1) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00011350,DAT_00011348,0xe0);
        uVar4 = 0xffffffff;
      }
      else {
        snprintf(param_1,0x14,DAT_00011344,lVar3);
        uVar4 = 0;
      }
    }
  }
  return uVar4;
}

