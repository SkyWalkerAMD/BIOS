
void downloadUserProfile_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *__s;
  size_t __n;
  undefined4 uVar7;
  undefined4 uVar8;
  void *__ptr;
  int iVar9;
  int iVar10;
  undefined1 auStack_54 [48];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_0012c9f4);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0012ca04);
    FCGI_printf(DAT_0012ca08);
    qcgires_setcontenttype(iVar2,DAT_0012ca0c);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_0012ca10,uVar7);
    uVar7 = json_object_new_string(DAT_0012ca14);
    json_object_object_add(uVar8,DAT_0012ca18,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0012ca1c,uVar7);
    json_object_put(uVar8);
    goto LAB_0012c59c;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012c9f8);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012c9fc,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012c9fc,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012ca00), iVar5 != 0))
    goto LAB_0012c4ec;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_0012ca24);
    pcVar6 = getenv(DAT_0012ca28);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_0012ca2c),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    if (*DAT_0012ca30 == 0) {
LAB_0012c694:
      iVar10 = FCGI_fopen(DAT_0012ca40,DAT_0012ca3c);
      if (iVar10 == 0) {
        IPMI_lo_Logout(auStack_54);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          iVar5 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_0012ca4c,0x26);
          json_object_object_add(iVar5,DAT_0012ca18,uVar8);
          uVar8 = json_object_new_int(DAT_0012ca50);
          json_object_object_add(iVar5,DAT_0012ca54,uVar8);
          uVar8 = DAT_0012ca58;
          goto LAB_0012c974;
        }
        strcasecmp(pcVar3,DAT_0012ca2c);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0012ca4c,0x26);
        json_object_object_add(iVar5,DAT_0012ca18,uVar8);
        uVar8 = json_object_new_int(DAT_0012ca50);
        json_object_object_add(iVar5,DAT_0012ca54,uVar8);
        uVar8 = DAT_0012ca58;
LAB_0012c83c:
        FCGI_printf(DAT_0012ca5c,uVar8);
        qcgires_setcontenttype(iVar2,DAT_0012ca0c);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0012ca1c,uVar8);
      }
      else {
        FCGI_fclose();
        FCGI_printf(DAT_0012ca44);
        FCGI_printf(DAT_0012ca48,DAT_0012ca40);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          IPMI_lo_Logout(auStack_54);
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          goto LAB_0012c57c;
        }
        strcasecmp(pcVar3,DAT_0012ca2c);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        IPMI_lo_Logout(auStack_54);
      }
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      strcasecmp(pcVar3,DAT_0012ca2c);
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012ca34);
      iVar10 = IPMI_lo_Login(DAT_0012ca38,DAT_0012ca38,auStack_54,uVar1,1,0,0,0);
      if (iVar10 == 0) goto LAB_0012c694;
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0012ca2c);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0012ca60,0x20);
        json_object_object_add(iVar5,DAT_0012ca18,uVar8);
        uVar8 = json_object_new_int(DAT_0012ca64);
        json_object_object_add(iVar5,DAT_0012ca54,uVar8);
        uVar8 = DAT_0012ca68;
        goto LAB_0012c83c;
      }
      iVar5 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_0012ca60,0x20);
      json_object_object_add(iVar5,DAT_0012ca18,uVar8);
      uVar8 = json_object_new_int(DAT_0012ca64);
      json_object_object_add(iVar5,DAT_0012ca54,uVar8);
      uVar8 = DAT_0012ca68;
LAB_0012c974:
      FCGI_printf(DAT_0012ca5c,uVar8);
      qcgires_setcontenttype(iVar2,DAT_0012ca0c);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0012ca1c,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  else {
LAB_0012c4ec:
    FCGI_printf(DAT_0012ca04);
    FCGI_printf(DAT_0012ca08);
    qcgires_setcontenttype(iVar2,DAT_0012ca0c);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0012ca10,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012ca00);
    uVar8 = DAT_0012ca14;
    if (iVar5 == 1) {
      uVar8 = DAT_0012ca20;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_0012ca18,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0012ca1c,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
LAB_0012c57c:
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0012c59c:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

