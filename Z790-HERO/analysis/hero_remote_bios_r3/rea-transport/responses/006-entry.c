
void entry(undefined8 param_1,longlong param_2)

{
  FUN_0000046c(param_1,param_2);
  FUN_00000580(param_1,param_2);
  return;
}




ulonglong FUN_0000292c(longlong param_1)

{
  ulonglong uVar1;
  ulonglong uVar2;
  short *psVar3;
  ulonglong uVar4;
  int local_res8 [2];
  ulonglong local_48 [2];
  char local_38;
  char local_37 [31];
  
  uVar2 = 0;
  if (param_1 == 0) {
    uVar2 = 0x8000000000000002;
  }
  else if (*(longlong *)(param_1 + 0x38) == 0) {
    uVar2 = 0x8000000000000013;
  }
  else {
    uVar1 = uVar2;
    if (*(short *)(param_1 + 0x52) == 0) {
      FUN_00003964(&local_38,0x19,(char *)(param_1 + 0x54));
    }
    else {
      FUN_00003bcc(&local_38,0x19,(byte *)s__a__d_00007238,param_1 + 0x54);
    }
    while (local_38 != '\0') {
      local_38 = local_37[uVar1];
      uVar1 = uVar1 + 1;
    }
    uVar4 = uVar2;
    for (psVar3 = *(short **)(param_1 + 0x38); *psVar3 != 0; psVar3 = psVar3 + 1) {
      uVar4 = uVar4 + 1;
    }
    uVar1 = (uVar1 + uVar4) * 2 + 0x12;
    psVar3 = (short *)FUN_00004aa0(psVar3,uVar1);
    if (psVar3 != (short *)0x0) {
      FUN_00003b9c((char *)psVar3,uVar1,(byte *)s_https____a_s_00007380,(ulonglong)&local_38);
      local_48[1] = 0;
      local_48[0] = 3;
      uVar2 = FUN_00004cb8((longlong *)local_48);
      if (-1 < (longlong)uVar2) {
        FUN_00004dfc(local_48,&DAT_00007250,&local_38);
        FUN_00004dfc(local_48,s_X_Auth_Token_000072d0,*(char **)(param_1 + 0x30));
        FUN_00004dfc(local_48,s_OData_Version_00007288,&DAT_00007280);
        local_res8[0] = 0;
        if (*(undefined8 **)(param_1 + 0x18) == (undefined8 *)0x0) {
          uVar2 = 0x8000000000000002;
        }
        else {
          uVar2 = FUN_00003348(*(undefined8 **)(param_1 + 0x18),7,psVar3,local_48,0,0,
                               (ulonglong *)0x0,(longlong *)0x0,(undefined8 *)0x0,local_res8);
        }
        if ((local_res8[0] - 3U & 0xfffffffb) != 0) {
          uVar2 = 0x8000000000000018;
        }
        if (-1 < (longlong)uVar2) {
          if (*(longlong *)(param_1 + 0x30) != 0) {
            (**(code **)(DAT_00007b28 + 0x48))();
            *(undefined8 *)(param_1 + 0x30) = 0;
          }
          if (*(longlong *)(param_1 + 0x38) != 0) {
            (**(code **)(DAT_00007b28 + 0x48))();
            *(undefined8 *)(param_1 + 0x38) = 0;
          }
        }
      }
      (**(code **)(DAT_00007b28 + 0x48))(psVar3);
    }
    FUN_00004d00(local_48);
  }
  return uVar2;
}

