
longlong FUN_000484c8(longlong param_1,undefined2 param_2,short *param_3)

{
  short *psVar1;
  longlong lVar2;
  char *pcVar3;
  longlong lVar4;
  longlong local_res20;
  short *local_38;
  longlong local_30;
  longlong local_28 [2];
  
  local_res20 = 0;
  local_30 = 0;
  lVar4 = 0;
  if (param_3 == (short *)0x0) {
    if (DAT_001935e0 == 0) {
      psVar1 = (short *)FUN_0000130c(u_PlatformLang_0016c188,&DAT_00109f58,(undefined4 *)0x0,
                                     &local_30);
      local_38 = psVar1;
      if (psVar1 != (short *)0x0) {
        (**(code **)(DAT_00180188 + 0x168))(&DAT_001935e0,0x28);
        (**(code **)(DAT_00180188 + 0x160))(&DAT_001935e0,psVar1,local_30);
        goto LAB_000485ab;
      }
    }
    else {
      psVar1 = (short *)FUN_000014c8(0x28);
      local_38 = psVar1;
      if (psVar1 != (short *)0x0) {
        FUN_000b07bc(psVar1,0x14,&DAT_001935e0);
        goto LAB_000485ab;
      }
    }
LAB_00048616:
    lVar2 = -0x7ffffffffffffff2;
LAB_00048620:
    if ((lVar2 < 0) && (local_res20 == 0)) {
      FUN_000013d0((longlong *)&local_38);
      psVar1 = (short *)FUN_000039c8(&DAT_0016c1a4);
      local_38 = psVar1;
      lVar2 = FUN_0004879c(param_1,psVar1,param_2,lVar4,&local_res20);
      if ((-1 < lVar2) || (local_res20 != 0)) {
LAB_000486f0:
        if (lVar2 == -0x7ffffffffffffffb) {
          lVar4 = FUN_000014c8(local_res20);
          if (lVar4 == 0) goto LAB_000485f5;
          lVar2 = FUN_0004879c(param_1,psVar1,param_2,lVar4,&local_res20);
          if (-1 < lVar2) goto LAB_00048777;
        }
        goto LAB_00048734;
      }
      pcVar3 = &DAT_0016c1a4;
      for (; ((char)*psVar1 != '\0' && ((char)*psVar1 == *pcVar3));
          psVar1 = (short *)((longlong)psVar1 + 1)) {
        pcVar3 = pcVar3 + 1;
      }
      if ((char)*psVar1 != *pcVar3) {
        FUN_000013d0((longlong *)&local_38);
        psVar1 = (short *)FUN_000039c8(&DAT_0016c1a4);
        local_38 = psVar1;
        lVar2 = FUN_0004879c(param_1,psVar1,param_2,lVar4,&local_res20);
        if ((-1 < lVar2) || (local_res20 != 0)) goto LAB_000486f0;
      }
    }
    else {
LAB_00048734:
      lVar4 = FUN_0000151c(local_res20);
      if (lVar4 == 0) goto LAB_000485f5;
      local_28[0] = lVar4;
      lVar2 = FUN_000b1684(param_1,param_2,(char *)psVar1,&local_res20,lVar4);
      if (lVar2 < 0) {
        FUN_000013d0(local_28);
        lVar4 = local_28[0];
      }
    }
LAB_00048777:
    FUN_000013d0((longlong *)&local_38);
  }
  else {
    psVar1 = (short *)FUN_00003acc(param_3);
    local_38 = psVar1;
LAB_000485ab:
    if (psVar1 == (short *)0x0) goto LAB_00048616;
    if (param_1 == -1) {
      param_1 = DAT_00193900;
    }
    lVar2 = FUN_000b1684(param_1,param_2,(char *)psVar1,&local_res20,0);
    lVar4 = 0;
    if (lVar2 != -0x7ffffffffffffffe) goto LAB_00048620;
    lVar4 = FUN_000014c8(2);
    if (lVar4 != 0) {
      lVar2 = FUN_000b1684(param_1,param_2,(char *)psVar1,&local_res20,lVar4);
      goto LAB_00048620;
    }
LAB_000485f5:
    lVar4 = 0;
  }
  return lVar4;
}

