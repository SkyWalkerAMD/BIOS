
void getBIOSUpgradeStatus_func(void)

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
  pcVar2 = getenv(DAT_0012e2d4);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_0012e2e4);
    FCGI_printf(DAT_0012e2e8);
    qcgires_setcontenttype(iVar1,DAT_0012e2ec);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0012e2f0,uVar6);
    uVar6 = json_object_new_string(DAT_0012e2f4);
    json_object_object_add(uVar7,DAT_0012e2f8,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0012e2fc,uVar6);
    json_object_put(uVar7);
    goto LAB_0012df34;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012e2d8);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0012e2dc,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0012e2dc,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012e2e0), iVar4 != 0))
    goto LAB_0012de84;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_0012e304);
    pcVar5 = getenv(DAT_0012e308);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_0012e30c),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    pcVar5 = (char *)(**(code **)(iVar1 + 0x18))(iVar1,DAT_0012e310,0);
    snprintf(acStack_10040,10,DAT_0012e2fc,pcVar5);
    uVar10 = strtol(pcVar5,(char **)0x0,10);
    uVar10 = uVar10 & 0xff;
    CMD_Get_Firmware_Progress(auStack_10034,uVar10,1,&uStack_10044,1);
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,DAT_0012e310,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,DAT_0012e314,uVar7);
      qcgires_setcontenttype(iVar1,DAT_0012e2ec);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_0012e2fc,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_0012e30c);
LAB_0012e1b8:
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
      }
    }
    else {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,DAT_0012e310,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,DAT_0012e314,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_0012e30c);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_0012e318,0x1f);
        json_object_object_add(iVar4,DAT_0012e2f8,uVar7);
        uVar7 = json_object_new_int(DAT_0012e31c);
        json_object_object_add(iVar4,DAT_0012e320,uVar7);
        FCGI_printf(DAT_0012e328,DAT_0012e324);
        qcgires_setcontenttype(iVar1,DAT_0012e2ec);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_0012e2fc,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_0012e30c);
        goto LAB_0012e1b8;
      }
      iVar4 = json_object_new_object();
      uVar7 = json_object_new_string_len(DAT_0012e318,0x1f);
      json_object_object_add(iVar4,DAT_0012e2f8,uVar7);
      uVar7 = json_object_new_int(DAT_0012e31c);
      json_object_object_add(iVar4,DAT_0012e320,uVar7);
      FCGI_printf(DAT_0012e328,DAT_0012e324);
      qcgires_setcontenttype(iVar1,DAT_0012e2ec);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_0012e2fc,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
    }
  }
  else {
LAB_0012de84:
    FCGI_printf(DAT_0012e2e4);
    FCGI_printf(DAT_0012e2e8);
    qcgires_setcontenttype(iVar1,DAT_0012e2ec);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_0012e2f0,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012e2e0);
    uVar7 = DAT_0012e2f4;
    if (iVar4 == 1) {
      uVar7 = DAT_0012e300;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_0012e2f8,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_0012e2fc,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_0012df34:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

