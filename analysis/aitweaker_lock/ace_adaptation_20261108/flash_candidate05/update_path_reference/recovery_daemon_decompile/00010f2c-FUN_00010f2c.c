
undefined4 FUN_00010f2c(void)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  pthread_t *__newthread;
  pthread_t pStack_24;
  
  iVar5 = unix_init();
  piVar1 = DAT_000110fc;
  if (iVar5 < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011134,DAT_0001111c,0x1e0);
  }
  else {
    RetrieveCoreFeatures(DAT_00011100);
    RetrieveCoreMacros(DAT_00011104,DAT_00011100);
    FUN_00011ec0();
    GetCompLibraryMetaData(DAT_0001110c,DAT_00011108,piVar1);
    printf(DAT_00011110,*piVar1);
    uVar4 = DAT_00011120;
    uVar3 = DAT_0001111c;
    uVar2 = DAT_00011118;
    if (0 < *piVar1) {
      iVar7 = 0;
      iVar5 = DAT_00011108;
      __newthread = DAT_00011114;
      do {
        iVar7 = iVar7 + 1;
        if ((*(__start_routine **)(iVar5 + 0x110) != (__start_routine *)0x0) &&
           (iVar6 = pthread_create(__newthread,(pthread_attr_t *)0x0,
                                   *(__start_routine **)(iVar5 + 0x110),(void *)0x0), iVar6 != 0)) {
          IDBG_LINUXAPP_DbgOut(0x82,uVar4,uVar3,uVar2);
        }
        iVar5 = iVar5 + 0x114;
        __newthread = __newthread + 1;
      } while (iVar7 < *piVar1);
    }
    if (*(int *)(DAT_00011100 + 0x1b0) == 1) {
      FUN_00011540();
    }
    uVar2 = DAT_00011124;
    iVar5 = FUN_000114d8(DAT_00011124);
    if (iVar5 < 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001114c,DAT_0001111c,DAT_00011148);
    }
    else {
      iVar5 = FUN_000114d8(DAT_00011128);
      if (iVar5 < 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0001113c,DAT_0001111c,DAT_00011138);
      }
      else {
        iVar5 = sigwrap_open(uVar2,2);
        piVar1[1] = iVar5;
        if (iVar5 == -1) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00011150,DAT_0001111c,0x210,uVar2);
        }
        else {
          iVar5 = pthread_create(&pStack_24,(pthread_attr_t *)0x0,DAT_0001112c,(void *)0x0);
          if (iVar5 == 0) {
            puts(DAT_00011130);
            do {
              pcie_log();
              sleep(5);
            } while( true );
          }
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00011144,DAT_0001111c,DAT_00011140);
        }
      }
    }
  }
  return 0xffffffff;
}

