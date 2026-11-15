
undefined4 link_feature_lib_spx_restservice_packs(void)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  code *pcVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  
  uVar3 = DAT_0002d7c0;
  uVar2 = DAT_0002d7bc;
  uVar1 = DAT_0002d7b8;
  puVar7 = DAT_0002d7b4 + 0x41;
  puVar6 = DAT_0002d7b4;
  do {
    iVar4 = IsFeatureEnabled(*puVar6);
    if (iVar4 != 0) {
      iVar4 = dlopen(puVar6[1],DAT_0002d7c4);
      puVar6[4] = iVar4;
      if (iVar4 == 0) {
        IDBG_LINUXAPP_DbgOut(0x82,uVar3,uVar1,DAT_0002d7c8);
      }
      else {
        pcVar5 = (code *)dlsym(iVar4,puVar6[2]);
        puVar6[3] = pcVar5;
        if (pcVar5 == (code *)0x0) {
          IDBG_LINUXAPP_DbgOut(0x82,uVar2,uVar1,DAT_0002d7cc);
          dlclose(puVar6[4]);
        }
        else {
          (*pcVar5)();
          dlclose(puVar6[4]);
        }
      }
    }
    puVar6 = puVar6 + 5;
  } while (puVar6 != puVar7);
  return 0;
}

