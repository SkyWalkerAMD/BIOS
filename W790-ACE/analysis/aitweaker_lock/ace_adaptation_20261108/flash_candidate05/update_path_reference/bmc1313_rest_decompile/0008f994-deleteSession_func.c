
void deleteSession_func(int param_1)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  size_t __n;
  undefined4 uVar8;
  undefined4 uVar9;
  void *__ptr;
  int iVar10;
  long lVar11;
  int iVar12;
  int iVar13;
  int local_68;
  undefined1 auStack_54 [48];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_00090064);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00090074);
    FCGI_printf(DAT_00090078);
    qcgires_setcontenttype(iVar2,DAT_0009007c);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_00090080,uVar8);
    uVar8 = json_object_new_string(DAT_00090084);
    json_object_object_add(uVar9,DAT_00090088,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_0009008c,uVar8);
    json_object_put(uVar9);
    goto LAB_0008fb10;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00090068);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0009006c,0);
    pcVar7 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0009006c,0);
    __n = strlen(pcVar7);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00090070), iVar5 != 0))
    goto LAB_0008fa60;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(5);
    local_68 = json_object_new_object();
    pcVar3 = getenv(DAT_00090094);
    pcVar6 = getenv(DAT_00090098);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_0009009c),
       iVar10 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(local_68);
      local_68 = json_tokener_parse(__ptr);
    }
    if (*DAT_000900a0 == 0) {
LAB_0008fc08:
      iVar10 = get_path_info();
      if (iVar10 == 0) {
LAB_0008fc7c:
        lVar11 = -1;
      }
      else {
        iVar12 = *(int *)(param_1 + 8);
        iVar13 = *(int *)(param_1 + 0xc) - iVar12;
        pcVar7 = calloc(iVar13 + 1,1);
        if (pcVar7 == (char *)0x0) goto LAB_0008fc7c;
        sprintf(pcVar7,DAT_000900ac,iVar13,iVar10 + iVar12);
        lVar11 = strtol(pcVar7,(char **)0x0,10);
        free(pcVar7);
      }
      iVar10 = LIBIPMI_HL_AMIActivedcloseSession(auStack_54,lVar11,0x1e);
      if (iVar10 == 0) {
        uVar9 = json_object_new_int();
        json_object_object_add(iVar5,DAT_00090080,uVar9);
        qcgires_setcontenttype(iVar2,DAT_0009007c);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0009008c,uVar9);
        IPMI_lo_Logout(auStack_54);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) goto LAB_0008faf0;
        strcasecmp(pcVar3,DAT_0009009c);
      }
      else {
        IPMI_lo_Logout(auStack_54);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          iVar5 = json_object_new_object();
          uVar9 = json_object_new_string_len(DAT_000900b0,0x16);
          json_object_object_add(iVar5,DAT_00090088,uVar9);
          uVar9 = json_object_new_int(DAT_000900b4);
          json_object_object_add(iVar5,DAT_000900b8,uVar9);
          uVar9 = DAT_000900bc;
          goto LAB_0008feb0;
        }
        iVar5 = strcasecmp(pcVar3,DAT_0009009c);
        if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
           (iVar5 = strcasecmp(pcVar3,DAT_000900d0), iVar5 == 0)) {
          strncasecmp(pcVar6,DAT_0009007c,0x10);
        }
        if (local_68 != 0) {
          json_object_put(local_68);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000900b0,0x16);
        json_object_object_add(iVar5,DAT_00090088,uVar9);
        uVar9 = json_object_new_int(DAT_000900b4);
        json_object_object_add(iVar5,DAT_000900b8,uVar9);
        uVar9 = DAT_000900bc;
LAB_0008fd2c:
        FCGI_printf(DAT_000900c0,uVar9);
        qcgires_setcontenttype(iVar2,DAT_0009007c);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0009008c,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_0009009c);
      }
      if (local_68 != 0) {
        json_object_put(local_68);
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000900a4);
      iVar10 = IPMI_lo_Login(DAT_000900a8,DAT_000900a8,auStack_54,uVar1,1,0,0,0);
      if (iVar10 == 0) goto LAB_0008fc08;
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        iVar5 = strcasecmp(pcVar3,DAT_0009009c);
        if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
           (iVar5 = strcasecmp(pcVar3,DAT_000900d0), iVar5 == 0)) {
          strncasecmp(pcVar6,DAT_0009007c,0x10);
        }
        if (local_68 != 0) {
          json_object_put(local_68);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000900c4,0x20);
        json_object_object_add(iVar5,DAT_00090088,uVar9);
        uVar9 = json_object_new_int(DAT_000900c8);
        json_object_object_add(iVar5,DAT_000900b8,uVar9);
        uVar9 = DAT_000900cc;
        goto LAB_0008fd2c;
      }
      iVar5 = json_object_new_object();
      uVar9 = json_object_new_string_len(DAT_000900c4,0x20);
      json_object_object_add(iVar5,DAT_00090088,uVar9);
      uVar9 = json_object_new_int(DAT_000900c8);
      json_object_object_add(iVar5,DAT_000900b8,uVar9);
      uVar9 = DAT_000900cc;
LAB_0008feb0:
      FCGI_printf(DAT_000900c0,uVar9);
      qcgires_setcontenttype(iVar2,DAT_0009007c);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0009008c,uVar9);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  else {
LAB_0008fa60:
    FCGI_printf(DAT_00090074);
    FCGI_printf(DAT_00090078);
    qcgires_setcontenttype(iVar2,DAT_0009007c);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_00090080,uVar9);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00090070);
    uVar9 = DAT_00090084;
    if (iVar5 == 1) {
      uVar9 = DAT_00090090;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_00090088,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0009008c,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar4);
  }
LAB_0008faf0:
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0008fb10:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

