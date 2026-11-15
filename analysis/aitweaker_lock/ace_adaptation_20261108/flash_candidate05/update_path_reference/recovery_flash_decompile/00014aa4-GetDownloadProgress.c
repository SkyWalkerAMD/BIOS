
undefined4 GetDownloadProgress(char *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  char *__filename;
  FILE *__stream;
  int iVar3;
  size_t sVar4;
  int iVar5;
  int *piVar6;
  char *pcVar7;
  int iVar8;
  char local_8c;
  char local_8b;
  char acStack_89 [60];
  char acStack_4d [33];
  char local_2c;
  
  __filename = DAT_00014d58;
  pcVar7 = DAT_00014d54;
  uVar2 = DAT_00014d50;
  uVar1 = DAT_00014d4c;
  iVar8 = 3;
  do {
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,uVar2,uVar1,DAT_00014d5c);
    __stream = fopen(__filename,pcVar7);
    if (__stream == (FILE *)0x0) {
      piVar6 = __errno_location();
      pcVar7 = strerror(*piVar6);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00014d8c,DAT_00014d4c,DAT_00014d88,pcVar7);
      return 5;
    }
    memset(&local_8c,0,0x61);
    fileno(__stream);
    iVar3 = file_lock_read();
    if (iVar3 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00014d78,uVar1,DAT_00014d74);
    }
    sVar4 = fread(&local_8c,0x61,1,__stream);
    if (sVar4 == 1) {
      if (iVar3 == 0) {
        fileno(__stream);
        file_unlock();
      }
      fclose(__stream);
      break;
    }
    iVar5 = feof(__stream);
    if (iVar5 == 0) {
      iVar8 = ferror(__stream);
      if (iVar8 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00014d84,DAT_00014d4c,DAT_00014d80);
      }
      if (iVar3 == 0) {
        fileno(__stream);
        file_unlock();
      }
      fclose(__stream);
      return 5;
    }
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00014d64,uVar1,DAT_00014d60);
    if (iVar3 == 0) {
      fileno(__stream);
      file_unlock();
    }
    fclose(__stream);
    puts(DAT_00014d68);
    sleep(1);
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  if ((local_8c == '\x02') || (local_8b == '\x04')) {
    strncpy(param_1,acStack_89,0x3c);
    param_1[0x3b] = '\0';
    strncpy(param_1 + 0x3c,acStack_4d,0x1e);
    param_1[0x59] = '\0';
    param_1[0x5a] = SUB41(acStack_4d._29_4_,1);
    param_1[0x5b] = SUB41(acStack_4d._29_4_,2);
    param_1[0x5c] = SUB41(acStack_4d._29_4_,3);
    param_1[0x5d] = local_2c;
  }
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00014d70,DAT_00014d4c,DAT_00014d6c);
  if ((local_8c == '\x02') && (*(int *)(param_1 + 0x5a) == 2)) {
    puts(DAT_00014d7c);
    if (*(int *)(param_1 + 0x5a) != 4) {
      return 0xff;
    }
  }
  else if (*(int *)(param_1 + 0x5a) != 4) {
    return 0;
  }
  return 0xfe;
}

