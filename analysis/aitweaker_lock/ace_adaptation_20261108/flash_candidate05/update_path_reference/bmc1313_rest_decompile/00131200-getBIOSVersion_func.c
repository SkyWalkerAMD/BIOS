
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
  pcVar3 = getenv(DAT_0013189c);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_001318ac);
    FCGI_printf(DAT_001318b0);
    qcgires_setcontenttype(iVar2,DAT_001318b4);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_001318b8,uVar8);
    uVar8 = json_object_new_string(DAT_001318bc);
    json_object_object_add(uVar9,DAT_001318c0,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_001318c4,uVar8);
    json_object_put(uVar9);
    goto LAB_0013137c;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_001318a0);
  if (pcVar3 == (char *)0x0 || iVar5 != 1) {
LAB_001312cc:
    FCGI_printf(DAT_001318ac);
    FCGI_printf(DAT_001318b0);
    qcgires_setcontenttype(iVar2,DAT_001318b4);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_001318b8,uVar9);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_001318a8);
    uVar9 = DAT_001318bc;
    if (iVar5 == 1) {
      uVar9 = DAT_001318c8;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_001318c0,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_001318c4,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar4);
  }
  else {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_001318a4,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_001318a4,0);
    sVar7 = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,sVar7);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_001318a8), iVar5 != 0))
    goto LAB_001312cc;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar10 = json_object_new_object();
    pcVar3 = getenv(DAT_001318cc);
    pcVar6 = getenv(DAT_001318d0);
    if ((pcVar3 != (char *)0x0) &&
       (iVar11 = strcasecmp(pcVar3,DAT_001318d4),
       iVar11 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(iVar10);
      iVar10 = json_tokener_parse(__ptr);
    }
    memset(auStack_101cc,0,0xcb);
    memset(auStack_10100,0,0xcb);
    uVar9 = (**(code **)(iVar2 + 0x24))(iVar2,DAT_001318d8);
    uVar1 = (**(code **)(iVar2 + 0x24))(iVar2,DAT_001318dc);
    CMD_Get_BIOS_Version(auStack_10034,uVar9,uVar1,1);
    if (iStack_10030 == 0) {
LAB_00131480:
      memcpy(auStack_101cc,auStack_1002a,0xcb);
      memcpy(auStack_10100,auStack_ff5f,0xcb);
      uVar9 = json_object_new_int(uStack_101c0);
      json_object_object_add(iVar5,DAT_001318e0,uVar9);
      uVar9 = json_object_new_int(uStack_101bf);
      json_object_object_add(iVar5,DAT_001318e4,uVar9);
      uVar9 = json_object_new_int(uStack_101c1);
      json_object_object_add(iVar5,DAT_001318e8,uVar9);
      sVar7 = strlen(acStack_101be);
      uVar9 = json_object_new_string_len(acStack_101be,sVar7);
      json_object_object_add(iVar5,DAT_001318ec,uVar9);
      sVar7 = strlen(acStack_10162);
      uVar9 = json_object_new_string_len(acStack_10162,sVar7);
      json_object_object_add(iVar5,DAT_001318f0,uVar9);
      uVar9 = json_object_new_int(uStack_100f4);
      json_object_object_add(iVar5,DAT_001318f4,uVar9);
      uVar9 = json_object_new_int(uStack_100f3);
      json_object_object_add(iVar5,DAT_001318f8,uVar9);
      uVar9 = json_object_new_int(uStack_100f5);
      json_object_object_add(iVar5,DAT_001318fc,uVar9);
      sVar7 = strlen(acStack_100f2);
      uVar9 = json_object_new_string_len(acStack_100f2,sVar7);
      json_object_object_add(iVar5,DAT_00131900,uVar9);
      sVar7 = strlen(acStack_10096);
      uVar9 = json_object_new_string_len(acStack_10096,sVar7);
      json_object_object_add(iVar5,DAT_00131904,uVar9);
      qcgires_setcontenttype(iVar2,DAT_001318b4);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_001318c4,uVar9);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_001318d4);
LAB_00131788:
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
            strcasecmp(pcVar3,DAT_001318d4);
            if (iVar10 != 0) {
              json_object_put(iVar10);
            }
            iVar5 = json_object_new_object();
            uVar9 = DAT_00131908;
            goto LAB_00131714;
          }
          iVar5 = json_object_new_object();
          uVar9 = DAT_00131908;
          goto LAB_001317ac;
        }
        goto LAB_00131480;
      }
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_001318d4);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = DAT_0013191c;
LAB_00131714:
        uVar9 = json_object_new_string_len(uVar9,0x1e);
        json_object_object_add(iVar5,DAT_001318c0,uVar9);
        uVar9 = json_object_new_int(DAT_0013190c);
        json_object_object_add(iVar5,DAT_00131910,uVar9);
        FCGI_printf(DAT_00131918,DAT_00131914);
        qcgires_setcontenttype(iVar2,DAT_001318b4);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_001318c4,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_001318d4);
        goto LAB_00131788;
      }
      iVar5 = json_object_new_object();
      uVar9 = DAT_0013191c;
LAB_001317ac:
      uVar9 = json_object_new_string_len(uVar9,0x1e);
      json_object_object_add(iVar5,DAT_001318c0,uVar9);
      uVar9 = json_object_new_int(DAT_0013190c);
      json_object_object_add(iVar5,DAT_00131910,uVar9);
      FCGI_printf(DAT_00131918,DAT_00131914);
      qcgires_setcontenttype(iVar2,DAT_001318b4);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_001318c4,uVar9);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0013137c:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

