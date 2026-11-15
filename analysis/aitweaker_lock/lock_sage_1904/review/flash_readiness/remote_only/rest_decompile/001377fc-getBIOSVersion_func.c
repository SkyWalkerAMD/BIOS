
void getBIOSVersion_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *__s;
  size_t sVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  void *__ptr;
  int iVar10;
  int iVar11;
  undefined1 auStack_101cc [11];
  undefined1 uStack_101c1;
  undefined1 uStack_101c0;
  undefined1 uStack_101bf;
  char acStack_101be [92];
  char acStack_10162 [98];
  undefined1 auStack_10100 [11];
  undefined1 uStack_100f5;
  undefined1 uStack_100f4;
  undefined1 uStack_100f3;
  char acStack_100f2 [92];
  char acStack_10096 [98];
  undefined1 auStack_10034 [4];
  int iStack_10030;
  undefined1 auStack_1002a [203];
  undefined1 auStack_ff5f [65339];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_00137e98);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00137ea8);
    FCGI_printf(DAT_00137eac);
    qcgires_setcontenttype(iVar2,DAT_00137eb0);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_00137eb4,uVar8);
    uVar8 = json_object_new_string(DAT_00137eb8);
    json_object_object_add(uVar9,DAT_00137ebc,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_00137ec0,uVar8);
    json_object_put(uVar9);
    goto LAB_00137978;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00137e9c);
  if (pcVar3 == (char *)0x0 || iVar5 != 1) {
LAB_001378c8:
    FCGI_printf(DAT_00137ea8);
    FCGI_printf(DAT_00137eac);
    qcgires_setcontenttype(iVar2,DAT_00137eb0);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_00137eb4,uVar9);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00137ea4);
    uVar9 = DAT_00137eb8;
    if (iVar5 == 1) {
      uVar9 = DAT_00137ec4;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_00137ebc,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_00137ec0,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar4);
  }
  else {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00137ea0,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00137ea0,0);
    sVar7 = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,sVar7);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00137ea4), iVar5 != 0))
    goto LAB_001378c8;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar10 = json_object_new_object();
    pcVar3 = getenv(DAT_00137ec8);
    pcVar6 = getenv(DAT_00137ecc);
    if ((pcVar3 != (char *)0x0) &&
       (iVar11 = strcasecmp(pcVar3,DAT_00137ed0),
       iVar11 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(iVar10);
      iVar10 = json_tokener_parse(__ptr);
    }
    memset(auStack_101cc,0,0xcb);
    memset(auStack_10100,0,0xcb);
    uVar9 = (**(code **)(iVar2 + 0x24))(iVar2,DAT_00137ed4);
    uVar1 = (**(code **)(iVar2 + 0x24))(iVar2,DAT_00137ed8);
    CMD_Get_BIOS_Version(auStack_10034,uVar9,uVar1,1);
    if (iStack_10030 == 0) {
LAB_00137a7c:
      memcpy(auStack_101cc,auStack_1002a,0xcb);
      memcpy(auStack_10100,auStack_ff5f,0xcb);
      uVar9 = json_object_new_int(uStack_101c0);
      json_object_object_add(iVar5,DAT_00137edc,uVar9);
      uVar9 = json_object_new_int(uStack_101bf);
      json_object_object_add(iVar5,DAT_00137ee0,uVar9);
      uVar9 = json_object_new_int(uStack_101c1);
      json_object_object_add(iVar5,DAT_00137ee4,uVar9);
      sVar7 = strlen(acStack_101be);
      uVar9 = json_object_new_string_len(acStack_101be,sVar7);
      json_object_object_add(iVar5,DAT_00137ee8,uVar9);
      sVar7 = strlen(acStack_10162);
      uVar9 = json_object_new_string_len(acStack_10162,sVar7);
      json_object_object_add(iVar5,DAT_00137eec,uVar9);
      uVar9 = json_object_new_int(uStack_100f4);
      json_object_object_add(iVar5,DAT_00137ef0,uVar9);
      uVar9 = json_object_new_int(uStack_100f3);
      json_object_object_add(iVar5,DAT_00137ef4,uVar9);
      uVar9 = json_object_new_int(uStack_100f5);
      json_object_object_add(iVar5,DAT_00137ef8,uVar9);
      sVar7 = strlen(acStack_100f2);
      uVar9 = json_object_new_string_len(acStack_100f2,sVar7);
      json_object_object_add(iVar5,DAT_00137efc,uVar9);
      sVar7 = strlen(acStack_10096);
      uVar9 = json_object_new_string_len(acStack_10096,sVar7);
      json_object_object_add(iVar5,DAT_00137f00,uVar9);
      qcgires_setcontenttype(iVar2,DAT_00137eb0);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_00137ec0,uVar9);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_00137ed0);
LAB_00137d84:
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
      }
    }
    else {
      if (iStack_10030 != 0xf1) {
        if (iStack_10030 != 0xf0) {
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 != (char *)0x0) {
            strcasecmp(pcVar3,DAT_00137ed0);
            if (iVar10 != 0) {
              json_object_put(iVar10);
            }
            iVar5 = json_object_new_object();
            uVar9 = DAT_00137f04;
            goto LAB_00137d10;
          }
          iVar5 = json_object_new_object();
          uVar9 = DAT_00137f04;
          goto LAB_00137da8;
        }
        goto LAB_00137a7c;
      }
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_00137ed0);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = DAT_00137f18;
LAB_00137d10:
        uVar9 = json_object_new_string_len(uVar9,0x1e);
        json_object_object_add(iVar5,DAT_00137ebc,uVar9);
        uVar9 = json_object_new_int(DAT_00137f08);
        json_object_object_add(iVar5,DAT_00137f0c,uVar9);
        FCGI_printf(DAT_00137f14,DAT_00137f10);
        qcgires_setcontenttype(iVar2,DAT_00137eb0);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00137ec0,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_00137ed0);
        goto LAB_00137d84;
      }
      iVar5 = json_object_new_object();
      uVar9 = DAT_00137f18;
LAB_00137da8:
      uVar9 = json_object_new_string_len(uVar9,0x1e);
      json_object_object_add(iVar5,DAT_00137ebc,uVar9);
      uVar9 = json_object_new_int(DAT_00137f08);
      json_object_object_add(iVar5,DAT_00137f0c,uVar9);
      FCGI_printf(DAT_00137f14,DAT_00137f10);
      qcgires_setcontenttype(iVar2,DAT_00137eb0);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_00137ec0,uVar9);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_00137978:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

