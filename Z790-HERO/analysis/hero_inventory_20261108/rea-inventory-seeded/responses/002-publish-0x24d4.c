
ulonglong UploadInventory_from_disassembly
                    (undefined8 *param_1,char *param_2,ulonglong param_3,char param_4)

{
  longlong lVar1;
  ulonglong uVar2;
  char *pcVar3;
  ulonglong uVar4;
  longlong lVar5;
  char *pcVar6;
  int local_res20 [2];
  char local_58 [16];
  ulonglong local_48;
  longlong local_40;
  
  pcVar3 = (char *)0x0;
  local_res20[0] = 3;
  local_40 = 0;
  local_48 = 2;
  uVar2 = FUN_0001888c((longlong *)&local_48);
  if (-1 < (longlong)uVar2) {
    if (param_4 == '\0') {
      uVar2 = 0;
      do {
        uVar4 = uVar2 + 1;
        lVar1 = uVar2 + 1;
        uVar2 = uVar4;
      } while (s_______WebKitFormBoundary7MA4YWxk_0001a410[lVar1] != '\0');
      lVar1 = 0;
      do {
        lVar5 = lVar1;
        lVar1 = lVar5 + 1;
      } while (s_______WebKitFormBoundary7MA4YWxk_0001a4c0[lVar5 + 1] != '\0');
      uVar2 = lVar5 + 1 + uVar4 + param_3;
      pcVar3 = (char *)FUN_00015ad4(uVar2 + 1);
      if (pcVar3 == (char *)0x0) {
        uVar2 = 0x8000000000000009;
        goto LAB_00002691;
      }
      if ((uVar4 != 0) && (pcVar3 != s_______WebKitFormBoundary7MA4YWxk_0001a410)) {
        FUN_00000280((undefined8 *)pcVar3,(undefined8 *)s_______WebKitFormBoundary7MA4YWxk_0001a410,
                     uVar4);
      }
      pcVar6 = pcVar3 + uVar4;
      if ((param_3 != 0) && (pcVar6 != param_2)) {
        FUN_00000280((undefined8 *)pcVar6,(undefined8 *)param_2,param_3);
      }
      if ((lVar5 + 2U != 0) && (pcVar6 + param_3 != s_______WebKitFormBoundary7MA4YWxk_0001a4c0)) {
        FUN_00000280((undefined8 *)(pcVar6 + param_3),
                     (undefined8 *)s_______WebKitFormBoundary7MA4YWxk_0001a4c0,lVar5 + 2U);
      }
      pcVar6 = s_multipart_form_data__boundary____0001a4f0;
    }
    else {
      pcVar6 = s_application_json_charset_utf_8_00019b50;
      pcVar3 = param_2;
      uVar2 = param_3;
    }
    FUN_00018950(&local_48,s_Content_Type_0001a400,pcVar6);
    FUN_00015c2c(local_58,10,&DAT_0001a534,uVar2);
    FUN_00018950(&local_48,s_Content_Length_0001a538,local_58);
    uVar2 = FUN_00018a80(param_1,(param_4 != '\0') + 1,u__redfish_v1_Oem_Ami_InventoryDat_0001a550,
                         &local_48,pcVar3,(ulonglong *)0x0,(longlong *)0x0,(ulonglong *)0x0,
                         local_res20);
    if (-1 < (longlong)uVar2) {
      if (local_res20[0] == 0x26) {
        uVar2 = 0x800000000000000b;
      }
      else if (((local_res20[0] - 3U & 0xfffffffa) != 0) || (local_res20[0] == 8)) {
        uVar2 = 0x8000000000000018;
      }
    }
  }
LAB_00002691:
  if (local_40 != 0) {
    FUN_000188d4(&local_48);
  }
  if ((param_4 == '\0') && (pcVar3 != (char *)0x0)) {
    (**(code **)(DAT_0001e070 + 0x48))(pcVar3);
  }
  return uVar2;
}

