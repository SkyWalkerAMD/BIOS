

longlong FUN_00000db0(void)

{
  char cVar1;
  longlong lVar2;
  short *local_res8;
  ulonglong local_res10 [3];
  
  lVar2 = FUN_000022e0();
  if (-1 < lVar2) {
    FUN_00007f7c((longlong *)&local_res8,local_res10);
    if (local_res8 == (short *)0x0) {
      lVar2 = -0x7ffffffffffffff2;
    }
    else {
      cVar1 = FUN_00003cbc(&DAT_00013b00,1);
      if (cVar1 != '\0') {
        FUN_00002d80('\0',0x14a90,local_res8,local_res10[0]);
      }
      lVar2 = FUN_000089c4(local_res8,local_res10[0]);
      (**(code **)(DAT_00016838 + 0x48))(local_res8);
      if (DAT_00014648 != 0) {
        (**(code **)(DAT_00016838 + 0x48))();
        DAT_00014648 = 0;
      }
      DAT_00014658 = 0;
      DAT_00014650 = 0;
    }
  }
  return lVar2;
}



longlong FUN_00009c78(undefined8 param_1,undefined2 param_2,ulonglong param_3,undefined1 param_4)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  char *pcVar4;
  longlong lVar5;
  longlong lVar6;
  undefined8 uVar7;
  char *pcVar8;
  char *pcVar9;
  ulonglong local_res18;
  undefined1 local_res20 [8];
  char *local_38 [2];
  
  local_38[0] = (char *)0x0;
  lVar6 = 0;
  uVar7 = param_1;
  local_res18 = param_3;
  local_res20[0] = param_4;
  pcVar3 = (char *)FUN_00009e44(param_1);
  if (pcVar3 != (char *)0x0) {
    FUN_00000658(uVar7,(longlong *)local_38);
    pcVar8 = pcVar3;
    pcVar9 = local_38[0];
    do {
      while( true ) {
        pcVar4 = s_BiosAttributeRegistry_a__d__d__d_00014aa8 + 0x21;
        if (pcVar9 != (char *)0x0) {
          pcVar4 = pcVar9;
        }
        pcVar4 = FUN_00000714(pcVar3,0,s_BiosAttributeRegistry_a__d__d__d_00014aa8 + 0x21,pcVar4);
        if (pcVar4 == (char *)0x0) goto LAB_00009df4;
        local_res18 = 0;
        lVar5 = (**(code **)(DAT_00016858 + 8))
                          (DAT_00016858,pcVar4,param_1,param_2,local_res20,&local_res18,0);
        if (lVar5 == -0x7ffffffffffffffb) {
          lVar6 = FUN_000041f4(local_res18);
          if ((lVar6 != 0) &&
             (lVar5 = (**(code **)(DAT_00016858 + 8))
                                (DAT_00016858,pcVar4,param_1,param_2,lVar6,&local_res18,0),
             lVar5 < 0)) {
            (**(code **)(DAT_00016838 + 0x48))(lVar6);
            lVar6 = 0;
          }
          goto LAB_00009df4;
        }
        if (lVar5 != -0x7fffffffffffffe0) goto LAB_00009df4;
        if (pcVar9 == (char *)0x0) break;
        (**(code **)(DAT_00016838 + 0x48))(pcVar9);
        pcVar9 = (char *)0x0;
      }
      for (; (*pcVar8 != '\0' && (*pcVar8 != ';')); pcVar8 = pcVar8 + 1) {
      }
      cVar2 = *pcVar8;
      pcVar1 = pcVar8 + 1;
      pcVar8 = (char *)0x0;
      if (cVar2 == ';') {
        pcVar8 = pcVar1;
      }
    } while (pcVar8 != (char *)0x0);
LAB_00009df4:
    (**(code **)(DAT_00016838 + 0x48))(pcVar3);
    if (pcVar9 != (char *)0x0) {
      (**(code **)(DAT_00016838 + 0x48))(pcVar9);
    }
    if (pcVar4 != (char *)0x0) {
      (**(code **)(DAT_00016838 + 0x48))(pcVar4);
    }
  }
  return lVar6;
}

