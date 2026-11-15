
void BIOSVerifyImage_func(void)

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
  undefined4 uStack_10040;
  undefined4 uStack_1003c;
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_00134ff8);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00135008);
    FCGI_printf(DAT_0013500c);
    qcgires_setcontenttype(iVar2,DAT_00135010);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_00135014,uVar7);
    uVar7 = json_object_new_string(DAT_00135018);
    json_object_object_add(uVar8,DAT_0013501c,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_00135020,uVar7);
    json_object_put(uVar8);
    goto LAB_00134c10;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00134ffc);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00135000,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00135000,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00135004), iVar5 != 0))
    goto LAB_00134b60;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_00135028);
    pcVar6 = getenv(DAT_0013502c);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_00135030),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_00135034);
    if (iVar10 == 0) {
      uVar1 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00135034);
      uVar1 = json_object_get_int64();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_00135038);
    if (iVar10 == 0) {
      uStack_10040 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00135038);
      uStack_10040 = json_object_get_int64();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_0013503c);
    if (iVar10 == 0) {
      uStack_1003c = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0013503c);
      uStack_1003c = json_object_get_int64();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_00135040);
    if (iVar10 == 0) {
      uVar8 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00135040);
      uVar8 = json_object_get_int64();
    }
    CMD_Verify_Firmware_Update(auStack_10034,uStack_1003c,uVar1,uVar8,uStack_10040,1);
    if (iStack_10030 == 0) {
      uVar8 = json_object_new_int(uVar1);
      json_object_object_add(iVar5,DAT_00135034,uVar8);
      qcgires_setcontenttype(iVar2,DAT_00135010);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_00135020,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_00135030);
        goto LAB_00134eec;
      }
    }
    else {
      uVar8 = json_object_new_int(uVar1);
      json_object_object_add(iVar5,DAT_00135034,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        iVar9 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_00135044,0x1f);
        json_object_object_add(iVar9,DAT_0013501c,uVar8);
        uVar8 = json_object_new_int(DAT_00135048);
        json_object_object_add(iVar9,DAT_0013504c,uVar8);
        FCGI_printf(DAT_00135054,DAT_00135050);
        qcgires_setcontenttype(iVar2,DAT_00135010);
        uVar8 = json_object_to_json_string(iVar9);
        FCGI_printf(DAT_00135020,uVar8);
      }
      else {
        strcasecmp(pcVar3,DAT_00135030);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_00135044,0x1f);
        json_object_object_add(iVar5,DAT_0013501c,uVar8);
        uVar8 = json_object_new_int(DAT_00135048);
        json_object_object_add(iVar5,DAT_0013504c,uVar8);
        FCGI_printf(DAT_00135054,DAT_00135050);
        qcgires_setcontenttype(iVar2,DAT_00135010);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00135020,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_00135030);
      }
LAB_00134eec:
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
  }
  else {
LAB_00134b60:
    FCGI_printf(DAT_00135008);
    FCGI_printf(DAT_0013500c);
    qcgires_setcontenttype(iVar2,DAT_00135010);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_00135014,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00135004);
    uVar8 = DAT_00135018;
    if (iVar5 == 1) {
      uVar8 = DAT_00135024;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_0013501c,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_00135020,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_00134c10:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x00134c2c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

