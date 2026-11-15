
void putBIOSStartFlashMode_func(void)

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
  undefined4 uStack_10044;
  undefined4 uStack_10040;
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_0012dd54);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0012dd64);
    FCGI_printf(DAT_0012dd68);
    qcgires_setcontenttype(iVar2,DAT_0012dd6c);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_0012dd70,uVar7);
    uVar7 = json_object_new_string(DAT_0012dd74);
    json_object_object_add(uVar8,DAT_0012dd78,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0012dd7c,uVar7);
    json_object_put(uVar8);
    goto LAB_0012d8b8;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012dd58);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012dd5c,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012dd5c,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012dd60), iVar5 != 0))
    goto LAB_0012d808;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_0012dd84);
    pcVar6 = getenv(DAT_0012dd88);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_0012dd8c),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_0012dd90);
    if (iVar10 == 0) {
      uVar1 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012dd90);
      uVar1 = json_object_get_int();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_0012dd94);
    if (iVar10 == 0) {
      uStack_10044 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012dd94);
      uStack_10044 = json_object_get_int();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_0012dd98);
    if (iVar10 == 0) {
      uVar8 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012dd98);
      uVar8 = json_object_get_int();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_0012dd9c);
    if (iVar10 == 0) {
      uStack_10040 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012dd9c);
      uStack_10040 = json_object_get_int();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_0012dda0);
    if (iVar10 == 0) {
      uVar7 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012dda0);
      uVar7 = json_object_get_int();
    }
    CMD_Start_Firmware_Update(auStack_10034,uVar8,uVar1,uVar7,uStack_10044,uStack_10040,1);
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(uVar1);
      json_object_object_add(iVar5,DAT_0012dd90,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar5,DAT_0012dd94,uVar7);
      uVar8 = json_object_new_int(uVar8);
      json_object_object_add(iVar5,DAT_0012dd98,uVar8);
      qcgires_setcontenttype(iVar2,DAT_0012dd6c);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0012dd7c,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0012dd8c);
        goto LAB_0012dc28;
      }
    }
    else {
      uVar7 = json_object_new_int(uVar1);
      json_object_object_add(iVar5,DAT_0012dd90,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar5,DAT_0012dd94,uVar7);
      uVar8 = json_object_new_int(uVar8);
      json_object_object_add(iVar5,DAT_0012dd98,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        iVar9 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0012dda4,0x1f);
        json_object_object_add(iVar9,DAT_0012dd78,uVar8);
        uVar8 = json_object_new_int(DAT_0012dda8);
        json_object_object_add(iVar9,DAT_0012ddac,uVar8);
        FCGI_printf(DAT_0012ddb4,DAT_0012ddb0);
        qcgires_setcontenttype(iVar2,DAT_0012dd6c);
        uVar8 = json_object_to_json_string(iVar9);
        FCGI_printf(DAT_0012dd7c,uVar8);
      }
      else {
        strcasecmp(pcVar3,DAT_0012dd8c);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0012dda4,0x1f);
        json_object_object_add(iVar5,DAT_0012dd78,uVar8);
        uVar8 = json_object_new_int(DAT_0012dda8);
        json_object_object_add(iVar5,DAT_0012ddac,uVar8);
        FCGI_printf(DAT_0012ddb4,DAT_0012ddb0);
        qcgires_setcontenttype(iVar2,DAT_0012dd6c);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0012dd7c,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_0012dd8c);
      }
LAB_0012dc28:
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
  }
  else {
LAB_0012d808:
    FCGI_printf(DAT_0012dd64);
    FCGI_printf(DAT_0012dd68);
    qcgires_setcontenttype(iVar2,DAT_0012dd6c);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0012dd70,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012dd60);
    uVar8 = DAT_0012dd74;
    if (iVar5 == 1) {
      uVar8 = DAT_0012dd80;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_0012dd78,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0012dd7c,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0012d8b8:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x0012d8d4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

