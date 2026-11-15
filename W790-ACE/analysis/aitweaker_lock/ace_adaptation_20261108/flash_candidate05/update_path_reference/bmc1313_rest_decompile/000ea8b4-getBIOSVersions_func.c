
void getBIOSVersions_func(void)

{
  int iVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  char *__s;
  size_t sVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  void *__ptr;
  int iVar9;
  int iVar10;
  char acStack_100d4 [47];
  undefined1 auStack_100a5 [113];
  undefined1 auStack_10034 [4];
  int iStack_10030;
  undefined1 auStack_1002a [65542];
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_000eaee8);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_000eaef8);
    FCGI_printf(DAT_000eaefc);
    qcgires_setcontenttype(iVar1,DAT_000eaf00);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_000eaf04,uVar7);
    uVar7 = json_object_new_string(DAT_000eaf08);
    json_object_object_add(uVar8,DAT_000eaf0c,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_000eaf10,uVar7);
    json_object_put(uVar8);
    goto LAB_000eaa30;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000eaeec);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000eaef0,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000eaef0,0);
    sVar6 = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,sVar6);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000eaef4), iVar4 != 0))
    goto LAB_000ea980;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar9 = json_object_new_object();
    pcVar2 = getenv(DAT_000eaf18);
    pcVar5 = getenv(DAT_000eaf1c);
    if ((pcVar2 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar2,DAT_000eaf20),
       iVar10 != 0 && (pcVar5 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    pcVar5 = acStack_100d4 + 0x14;
    acStack_100d4[4] = '\0';
    acStack_100d4[5] = '\0';
    acStack_100d4[6] = '\0';
    acStack_100d4[7] = '\0';
    acStack_100d4[8] = '\0';
    acStack_100d4[9] = '\0';
    acStack_100d4[10] = '\0';
    acStack_100d4[0xb] = '\0';
    acStack_100d4[0xc] = '\0';
    acStack_100d4[0xd] = '\0';
    acStack_100d4[0xe] = '\0';
    acStack_100d4[0xf] = '\0';
    acStack_100d4[0x10] = '\0';
    acStack_100d4[0x11] = '\0';
    acStack_100d4[0x12] = '\0';
    acStack_100d4[0x13] = '\0';
    acStack_100d4[0] = '\0';
    acStack_100d4[1] = '\0';
    acStack_100d4[2] = '\0';
    acStack_100d4[3] = '\0';
    acStack_100d4[0x14] = '\0';
    acStack_100d4[0x15] = '\0';
    acStack_100d4[0x16] = '\0';
    acStack_100d4[0x17] = '\0';
    acStack_100d4[0x18] = '\0';
    acStack_100d4[0x19] = '\0';
    acStack_100d4[0x1a] = '\0';
    acStack_100d4[0x1b] = '\0';
    acStack_100d4[0x1c] = '\0';
    acStack_100d4[0x1d] = '\0';
    acStack_100d4[0x1e] = '\0';
    acStack_100d4[0x1f] = '\0';
    acStack_100d4[0x20] = '\0';
    acStack_100d4[0x21] = '\0';
    acStack_100d4[0x22] = '\0';
    acStack_100d4[0x23] = '\0';
    acStack_100d4[0x24] = '\0';
    acStack_100d4[0x25] = '\0';
    acStack_100d4[0x26] = '\0';
    acStack_100d4[0x27] = '\0';
    memset(acStack_100d4 + 0x28,0,0x78);
    CMD_Get_BIOSFirmware_Version(auStack_10034,1);
    if (iStack_10030 == 0) {
      memcpy(acStack_100d4 + 0x28,auStack_1002a,0x78);
      snprintf(acStack_100d4,0x14,DAT_000eaf10,auStack_100a5);
      memset(acStack_100d4 + 0x28,0,0x78);
      CMD_Get_BIOSFirmware_Version(auStack_10034,2);
      if (iStack_10030 != 0) {
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar2 != (char *)0x0) {
          strcasecmp(pcVar2,DAT_000eaf20);
          if (iVar9 != 0) {
            json_object_put(iVar9);
          }
          iVar4 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000eaf38,0x26);
          json_object_object_add(iVar4,DAT_000eaf0c,uVar8);
          uVar8 = DAT_000eaf3c;
          goto LAB_000eabac;
        }
        iVar4 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000eaf38,0x26);
        json_object_object_add(iVar4,DAT_000eaf0c,uVar8);
        uVar8 = DAT_000eaf3c;
        goto LAB_000eae68;
      }
      memcpy(acStack_100d4 + 0x28,auStack_1002a,0x78);
      snprintf(pcVar5,0x14,DAT_000eaf10,auStack_100a5);
      sVar6 = strlen(acStack_100d4);
      uVar8 = json_object_new_string_len(acStack_100d4,sVar6);
      json_object_object_add(iVar4,DAT_000eaf40,uVar8);
      sVar6 = strlen(pcVar5);
      uVar8 = json_object_new_string_len(pcVar5,sVar6);
      json_object_object_add(iVar4,DAT_000eaf44,uVar8);
      qcgires_setcontenttype(iVar1,DAT_000eaf00);
      uVar8 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000eaf10,uVar8);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_000eaf20);
        goto LAB_000eac08;
      }
    }
    else {
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 == (char *)0x0) {
        iVar4 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000eaf24,0x26);
        json_object_object_add(iVar4,DAT_000eaf0c,uVar8);
        uVar8 = DAT_000eaf28;
LAB_000eae68:
        uVar8 = json_object_new_int(uVar8);
        json_object_object_add(iVar4,DAT_000eaf2c,uVar8);
        FCGI_printf(DAT_000eaf34,DAT_000eaf30);
        qcgires_setcontenttype(iVar1,DAT_000eaf00);
        uVar8 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_000eaf10,uVar8);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        strcasecmp(pcVar2,DAT_000eaf20);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar4 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000eaf24,0x26);
        json_object_object_add(iVar4,DAT_000eaf0c,uVar8);
        uVar8 = DAT_000eaf28;
LAB_000eabac:
        uVar8 = json_object_new_int(uVar8);
        json_object_object_add(iVar4,DAT_000eaf2c,uVar8);
        FCGI_printf(DAT_000eaf34,DAT_000eaf30);
        qcgires_setcontenttype(iVar1,DAT_000eaf00);
        uVar8 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_000eaf10,uVar8);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_000eaf20);
LAB_000eac08:
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
      }
    }
  }
  else {
LAB_000ea980:
    FCGI_printf(DAT_000eaef8);
    FCGI_printf(DAT_000eaefc);
    qcgires_setcontenttype(iVar1,DAT_000eaf00);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_000eaf04,uVar8);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000eaef4);
    uVar8 = DAT_000eaf08;
    if (iVar4 == 1) {
      uVar8 = DAT_000eaf14;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_000eaf0c,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_000eaf10,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_000eaa30:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

