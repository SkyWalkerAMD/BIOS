
void dwldFWStatus_func(void)

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
  char acStack_80 [60];
  char acStack_44 [30];
  undefined4 local_26;
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_000e8de0);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_000e8df0);
    FCGI_printf(DAT_000e8df4);
    qcgires_setcontenttype(iVar1,DAT_000e8df8);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_000e8dfc,uVar7);
    uVar7 = json_object_new_string(DAT_000e8e00);
    json_object_object_add(uVar8,DAT_000e8e04,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_000e8e08,uVar7);
    json_object_put(uVar8);
    goto LAB_000e8a5c;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e8de4);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000e8de8,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000e8de8,0);
    sVar6 = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,sVar6);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e8dec), iVar4 != 0))
    goto LAB_000e89ac;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar9 = json_object_new_object();
    pcVar2 = getenv(DAT_000e8e10);
    pcVar5 = getenv(DAT_000e8e14);
    if ((pcVar2 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar2,DAT_000e8e18),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    iVar10 = GetDownloadProgress(acStack_80);
    if (iVar10 == 0xff) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000e8e38,DAT_000e8e34,DAT_000e8e30);
LAB_000e8c64:
      uVar8 = json_object_new_int(1);
      json_object_object_add(iVar4,DAT_000e8e3c,uVar8);
      sVar6 = strlen(acStack_80);
      uVar8 = json_object_new_string_len(acStack_80,sVar6);
      json_object_object_add(iVar4,DAT_000e8e40,uVar8);
      sVar6 = strlen(acStack_44);
      uVar8 = json_object_new_string_len(acStack_44,sVar6);
      json_object_object_add(iVar4,DAT_000e8e44,uVar8);
      uVar8 = json_object_new_int(local_26);
      json_object_object_add(iVar4,DAT_000e8e48,uVar8);
      qcgires_setcontenttype(iVar1,DAT_000e8df8);
      uVar8 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000e8e08,uVar8);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_000e8e18);
LAB_000e8d38:
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
      }
    }
    else {
      if (iVar10 == 0) goto LAB_000e8c64;
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_000e8e18);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar4 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000e8e1c,0x32);
        json_object_object_add(iVar4,DAT_000e8e04,uVar8);
        uVar8 = json_object_new_int(DAT_000e8e20);
        json_object_object_add(iVar4,DAT_000e8e24,uVar8);
        FCGI_printf(DAT_000e8e2c,DAT_000e8e28);
        qcgires_setcontenttype(iVar1,DAT_000e8df8);
        uVar8 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_000e8e08,uVar8);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_000e8e18);
        goto LAB_000e8d38;
      }
      iVar4 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000e8e1c,0x32);
      json_object_object_add(iVar4,DAT_000e8e04,uVar8);
      uVar8 = json_object_new_int(DAT_000e8e20);
      json_object_object_add(iVar4,DAT_000e8e24,uVar8);
      FCGI_printf(DAT_000e8e2c,DAT_000e8e28);
      qcgires_setcontenttype(iVar1,DAT_000e8df8);
      uVar8 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000e8e08,uVar8);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
    }
  }
  else {
LAB_000e89ac:
    FCGI_printf(DAT_000e8df0);
    FCGI_printf(DAT_000e8df4);
    qcgires_setcontenttype(iVar1,DAT_000e8df8);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_000e8dfc,uVar8);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e8dec);
    uVar8 = DAT_000e8e00;
    if (iVar4 == 1) {
      uVar8 = DAT_000e8e0c;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_000e8e04,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_000e8e08,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_000e8a5c:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

