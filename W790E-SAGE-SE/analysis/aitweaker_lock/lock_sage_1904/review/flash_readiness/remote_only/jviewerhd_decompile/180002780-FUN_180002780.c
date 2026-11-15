
int FUN_180002780(longlong param_1,char *param_2,undefined8 param_3,undefined8 param_4)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  longlong lVar4;
  char *pcVar5;
  undefined4 uVar6;
  
  uVar6 = (undefined4)param_3;
  if (*(char *)(param_1 + 0x18) != '\0') {
    FUN_180004430("Device is already in open state\n",param_2,param_3,param_4);
    return -0xc;
  }
  malloc(0x14);
  *(undefined8 *)(param_1 + 0x30) = 0;
  *(undefined8 *)(param_1 + 0x38) = 0;
  *(undefined8 *)(param_1 + 0x40) = 0;
  *(undefined8 *)(param_1 + 0x48) = 0;
  pcVar3 = strtok(param_2,"-");
  do {
    if (pcVar3 == (char *)0x0) {
      *(undefined4 *)(param_1 + 8) = uVar6;
      iVar2 = FUN_180002250(param_1);
      if (-1 < iVar2) {
        FUN_1800043d0("Start Redirecting the Harddisk device %c\n",param_1 + 0x30,param_3,param_4);
        *(undefined1 *)(param_1 + 0x18) = 1;
        *(undefined1 *)(param_1 + 0x24) = 1;
      }
      return iVar2;
    }
    lVar4 = -1;
    pcVar5 = (char *)(param_1 + 0x30);
    do {
      if (lVar4 == 0) break;
      lVar4 = lVar4 + -1;
      cVar1 = *pcVar5;
      pcVar5 = pcVar5 + 1;
    } while (cVar1 != '\0');
    if (lVar4 == -2) {
      lVar4 = param_1 - (longlong)pcVar3;
      do {
        cVar1 = *pcVar3;
        pcVar3 = pcVar3 + 1;
        pcVar3[lVar4 + 0x2f] = cVar1;
      } while (cVar1 != '\0');
    }
    else {
      lVar4 = -1;
      pcVar5 = (char *)(param_1 + 0x40);
      do {
        if (lVar4 == 0) break;
        lVar4 = lVar4 + -1;
        cVar1 = *pcVar5;
        pcVar5 = pcVar5 + 1;
      } while (cVar1 != '\0');
      if (lVar4 == -2) {
        lVar4 = param_1 - (longlong)pcVar3;
        do {
          cVar1 = *pcVar3;
          pcVar3 = pcVar3 + 1;
          pcVar3[lVar4 + 0x3f] = cVar1;
        } while (cVar1 != '\0');
      }
    }
    pcVar3 = strtok((char *)0x0,"-");
  } while( true );
}

