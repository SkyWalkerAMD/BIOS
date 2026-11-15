
ulonglong FUN_00019384(undefined8 *param_1,short *param_2,char *param_3,ulonglong param_4,
                      undefined8 *param_5)

{
  char cVar1;
  ulonglong uVar2;
  undefined8 *puVar3;
  ulonglong uVar4;
  longlong lVar5;
  char *pcVar6;
  char *pcVar7;
  ulonglong uVar8;
  undefined8 *puVar9;
  int local_58 [2];
  char local_50 [16];
  ulonglong local_40;
  longlong local_38;
  ulonglong local_30;
  undefined8 *local_28;
  
  local_28 = (undefined8 *)0x0;
  local_30 = 0;
  local_38 = 0;
  local_58[0] = 3;
  local_40 = 3;
  uVar4 = FUN_0001888c((longlong *)&local_40);
  if (-1 < (longlong)uVar4) {
    FUN_00018950(&local_40,s_Content_Type_0001a400,s_application_json_charset_utf_8_00019b50);
    FUN_00015c2c(local_50,10,&DAT_0001a534,param_4);
    FUN_00018950(&local_40,s_Content_Length_0001a538,local_50);
    FUN_00018950(&local_40,s_OData_Version_00019b80,&DAT_00019b78);
    uVar4 = FUN_00018a80(param_1,1,param_2,&local_40,param_3,&local_30,(longlong *)0x0,
                         (ulonglong *)0x0,local_58);
    puVar3 = local_28;
    uVar2 = local_30;
    if (-1 < (longlong)uVar4) {
      if (local_58[0] == 0x26) {
        uVar4 = 0x800000000000000b;
      }
      else if (((local_58[0] - 3U & 0xfffffffa) == 0) && (local_58[0] != 8)) {
        if (param_5 != (undefined8 *)0x0) {
          if (local_28 == (undefined8 *)0x0) goto LAB_0001956a;
          uVar8 = 0;
          puVar9 = local_28;
          if (local_30 != 0) {
            do {
              if (((char *)*puVar9 != (char *)0x0) &&
                 (lVar5 = FUN_00015b00((char *)*puVar9,s_Location_0001e028), lVar5 == 0)) {
                puVar9 = puVar3 + uVar8 * 2;
                if (puVar9 != (undefined8 *)0x0) {
                  lVar5 = 0;
                  cVar1 = *(char *)puVar9[1];
                  while (cVar1 != '\0') {
                    lVar5 = lVar5 + 1;
                    cVar1 = ((char *)puVar9[1])[lVar5];
                  }
                  pcVar6 = (char *)FUN_00015ad4(lVar5 + 1);
                  *param_5 = pcVar6;
                  if (pcVar6 == (char *)0x0) {
                    uVar4 = 0x8000000000000009;
                  }
                  else {
                    for (pcVar7 = (char *)puVar9[1]; *pcVar7 != '\0'; pcVar7 = pcVar7 + 1) {
                      *pcVar6 = *pcVar7;
                      pcVar6 = pcVar6 + 1;
                    }
                    *pcVar6 = '\0';
                  }
                }
                break;
              }
              uVar8 = uVar8 + 1;
              puVar9 = puVar9 + 2;
            } while (uVar8 < uVar2);
          }
        }
      }
      else {
        uVar4 = 0x8000000000000018;
      }
    }
    if (puVar3 != (undefined8 *)0x0) {
      FUN_000188d4(&local_30);
    }
  }
LAB_0001956a:
  if (local_38 != 0) {
    FUN_000188d4(&local_40);
  }
  return uVar4;
}

