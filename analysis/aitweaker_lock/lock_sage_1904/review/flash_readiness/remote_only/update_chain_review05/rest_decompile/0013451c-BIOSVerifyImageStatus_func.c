
void BIOSVerifyImageStatus_func(void)

{
  int iVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  char *__s;
  size_t __n;
  undefined4 uVar6;
  undefined4 uVar7;
  void *__ptr;
  int iVar8;
  int iVar9;
  uint uVar10;
  undefined4 uStack_10044;
  char acStack_10040 [12];
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_00134a3c);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_00134a4c);
    FCGI_printf(DAT_00134a50);
    qcgires_setcontenttype(iVar1,DAT_00134a54);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_00134a58,uVar6);
    uVar6 = json_object_new_string(DAT_00134a5c);
    json_object_object_add(uVar7,DAT_00134a60,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_00134a64,uVar6);
    json_object_put(uVar7);
    goto LAB_00134698;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_00134a40);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_00134a44,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_00134a44,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_00134a48), iVar4 != 0))
    goto LAB_001345e8;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_00134a6c);
    pcVar5 = getenv(DAT_00134a70);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_00134a74),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    pcVar5 = (char *)(**(code **)(iVar1 + 0x18))(iVar1,DAT_00134a78,0);
    snprintf(acStack_10040,10,DAT_00134a64,pcVar5);
    uVar10 = strtol(pcVar5,(char **)0x0,10);
    uVar10 = uVar10 & 0xff;
    CMD_Get_Firmware_Progress(auStack_10034,uVar10,2,&uStack_10044,1);
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,DAT_00134a78,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,DAT_00134a7c,uVar7);
      qcgires_setcontenttype(iVar1,DAT_00134a54);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_00134a64,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_00134a74);
LAB_00134920:
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
      }
    }
    else {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,DAT_00134a78,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,DAT_00134a7c,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_00134a74);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_00134a80,0x1f);
        json_object_object_add(iVar4,DAT_00134a60,uVar7);
        uVar7 = json_object_new_int(DAT_00134a84);
        json_object_object_add(iVar4,DAT_00134a88,uVar7);
        FCGI_printf(DAT_00134a90,DAT_00134a8c);
        qcgires_setcontenttype(iVar1,DAT_00134a54);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_00134a64,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_00134a74);
        goto LAB_00134920;
      }
      iVar4 = json_object_new_object();
      uVar7 = json_object_new_string_len(DAT_00134a80,0x1f);
      json_object_object_add(iVar4,DAT_00134a60,uVar7);
      uVar7 = json_object_new_int(DAT_00134a84);
      json_object_object_add(iVar4,DAT_00134a88,uVar7);
      FCGI_printf(DAT_00134a90,DAT_00134a8c);
      qcgires_setcontenttype(iVar1,DAT_00134a54);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_00134a64,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
    }
  }
  else {
LAB_001345e8:
    FCGI_printf(DAT_00134a4c);
    FCGI_printf(DAT_00134a50);
    qcgires_setcontenttype(iVar1,DAT_00134a54);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_00134a58,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_00134a48);
    uVar7 = DAT_00134a5c;
    if (iVar4 == 1) {
      uVar7 = DAT_00134a68;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_00134a60,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_00134a64,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_00134698:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

