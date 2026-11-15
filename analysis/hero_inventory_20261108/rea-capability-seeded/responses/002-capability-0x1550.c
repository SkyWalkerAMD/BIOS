
ulonglong RestJsonRequest_from_disassembly
                    (longlong param_1,char *param_2,undefined8 *param_3,ulonglong *param_4,
                    char param_5,char param_6)

{
  char cVar1;
  longlong lVar2;
  char *pcVar3;
  ulonglong extraout_RAX;
  longlong lVar4;
  ulonglong uVar5;
  char local_38;
  char local_37 [31];
  
  lVar4 = 0;
  lVar2 = lVar4;
  if (*(short *)(param_1 + 0x52) == 0) {
    FUN_00003964(&local_38,0x19,(char *)(param_1 + 0x54));
  }
  else {
    FUN_00003bcc(&local_38,0x19,(byte *)s__a__d_00007238,param_1 + 0x54);
  }
  while (local_38 != '\0') {
    local_38 = local_37[lVar2];
    lVar2 = lVar2 + 1;
  }
  cVar1 = *param_2;
  while (cVar1 != '\0') {
    lVar4 = lVar4 + 1;
    cVar1 = param_2[lVar4];
  }
  uVar5 = (lVar2 + lVar4) * 2 + 0x12;
  pcVar3 = (char *)FUN_00004aa0(lVar4,uVar5);
  *param_3 = pcVar3;
  if (pcVar3 == (char *)0x0) {
    uVar5 = 0x8000000000000009;
  }
  else {
    FUN_00003b9c(pcVar3,uVar5,(byte *)s_https____a_a_00007240,(ulonglong)&local_38);
    *param_4 = 3;
    uVar5 = *param_4;
    if (param_6 != '\0') {
      uVar5 = 5;
    }
    param_4[1] = 0;
    *param_4 = uVar5;
    if ((param_5 != '\0') && ((byte)(*(char *)(param_1 + 100) - 1U) < 2)) {
      *param_4 = *param_4 + 1;
    }
    uVar5 = FUN_00004cb8((longlong *)param_4);
    if (-1 < (longlong)uVar5) {
      FUN_00004dfc(param_4,&DAT_00007250,&local_38);
      FUN_00004dfc(param_4,s_Accept_00007278,s_application_json_charset_utf_8_00007258);
      FUN_00004dfc(param_4,s_OData_Version_00007288,&DAT_00007280);
      if (param_6 != '\0') {
        FUN_00004dfc(param_4,s_BiosRedfishVersion_000072a0,s_1_8_0_00007298);
        FUN_00004dfc(param_4,s_BiosRtpVersion_000072c0,s_1_8_a_000072b4);
      }
      if (param_5 != '\0') {
        if (*(char *)(param_1 + 100) == '\x01') {
          FUN_00003164(param_1,param_4);
          uVar5 = extraout_RAX;
        }
        else if (*(char *)(param_1 + 100) == '\x02') {
          FUN_00004dfc(param_4,s_X_Auth_Token_000072d0,*(char **)(param_1 + 0x30));
        }
      }
    }
  }
  return uVar5;
}

