
void setBIOSPrepareComponents_func(void)

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
  int iVar11;
  uint uVar12;
  undefined4 uStack_10048;
  uint uStack_10044;
  undefined1 uStack_10035;
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_0012d6d0);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0012d6e0);
    FCGI_printf(DAT_0012d6e4);
    qcgires_setcontenttype(iVar2,DAT_0012d6e8);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_0012d6ec,uVar7);
    uVar7 = json_object_new_string(DAT_0012d6f0);
    json_object_object_add(uVar8,DAT_0012d6f4,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0012d6f8,uVar7);
    json_object_put(uVar8);
    goto LAB_0012d230;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012d6d4);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012d6d8,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012d6d8,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012d6dc), iVar5 != 0))
    goto LAB_0012d180;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_0012d700);
    pcVar6 = getenv(DAT_0012d704);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_0012d708),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    uStack_10035 = 1;
    iVar10 = FCGI_fopen(DAT_0012d710,DAT_0012d70c);
    if (iVar10 != 0) {
      FCGI_fwrite(&uStack_10035,1,1);
    }
    unlink(DAT_0012d714);
    iVar11 = json_object_object_get_rest(iVar9,DAT_0012d718);
    if (iVar11 == 0) {
      uVar12 = 0xffffffff;
      uStack_10044 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012d718);
      uVar12 = json_object_get_int();
      uStack_10044 = uVar12 & 0xff;
    }
    iVar11 = json_object_object_get_rest(iVar9,DAT_0012d71c);
    if (iVar11 == 0) {
      uStack_10048 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012d71c);
      uStack_10048 = json_object_get_int();
    }
    iVar11 = json_object_object_get_rest(iVar9,DAT_0012d720);
    if (iVar11 == 0) {
      uVar8 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012d720);
      uVar8 = json_object_get_int();
    }
    iVar11 = json_object_object_get_rest(iVar9,DAT_0012d724);
    if (iVar11 == 0) {
      uVar1 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012d724);
      uVar1 = json_object_get_int();
    }
    CMD_Prepare_FW_Update(auStack_10034,uVar8,uStack_10044,uStack_10048,uVar1,0,1);
    uVar7 = json_object_new_int(uVar12);
    json_object_object_add(iVar5,DAT_0012d718,uVar7);
    uVar7 = json_object_new_int(uStack_10048);
    json_object_object_add(iVar5,DAT_0012d71c,uVar7);
    uVar8 = json_object_new_int(uVar8);
    json_object_object_add(iVar5,DAT_0012d720,uVar8);
    if (iStack_10030 == 0) {
      if (iVar10 != 0) {
        FCGI_fclose(iVar10);
      }
      qcgires_setcontenttype(iVar2,DAT_0012d6e8);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0012d6f8,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0012d708);
        goto LAB_0012d538;
      }
    }
    else {
      if (iVar10 != 0) {
        uStack_10035 = 0;
        FCGI_fwrite(&uStack_10035,1,1,iVar10);
        FCGI_fclose(iVar10);
      }
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        iVar9 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0012d728,0x1f);
        json_object_object_add(iVar9,DAT_0012d6f4,uVar8);
        uVar8 = json_object_new_int(DAT_0012d72c);
        json_object_object_add(iVar9,DAT_0012d730,uVar8);
        FCGI_printf(DAT_0012d738,DAT_0012d734);
        qcgires_setcontenttype(iVar2,DAT_0012d6e8);
        uVar8 = json_object_to_json_string(iVar9);
        FCGI_printf(DAT_0012d6f8,uVar8);
      }
      else {
        strcasecmp(pcVar3,DAT_0012d708);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0012d728,0x1f);
        json_object_object_add(iVar5,DAT_0012d6f4,uVar8);
        uVar8 = json_object_new_int(DAT_0012d72c);
        json_object_object_add(iVar5,DAT_0012d730,uVar8);
        FCGI_printf(DAT_0012d738,DAT_0012d734);
        qcgires_setcontenttype(iVar2,DAT_0012d6e8);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0012d6f8,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_0012d708);
      }
LAB_0012d538:
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
  }
  else {
LAB_0012d180:
    FCGI_printf(DAT_0012d6e0);
    FCGI_printf(DAT_0012d6e4);
    qcgires_setcontenttype(iVar2,DAT_0012d6e8);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0012d6ec,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012d6dc);
    uVar8 = DAT_0012d6f0;
    if (iVar5 == 1) {
      uVar8 = DAT_0012d6fc;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_0012d6f4,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0012d6f8,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0012d230:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

