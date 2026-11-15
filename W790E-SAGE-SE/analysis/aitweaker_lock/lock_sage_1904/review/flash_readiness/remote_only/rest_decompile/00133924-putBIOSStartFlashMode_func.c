
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
  undefined4 uStack_10048;
  undefined4 uStack_10044;
  undefined4 uStack_10040;
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_00133f44);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00133f54);
    FCGI_printf(DAT_00133f58);
    qcgires_setcontenttype(iVar2,DAT_00133f5c);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_00133f60,uVar7);
    uVar7 = json_object_new_string(DAT_00133f64);
    json_object_object_add(uVar8,DAT_00133f68,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_00133f6c,uVar7);
    json_object_put(uVar8);
    goto LAB_00133aa0;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00133f48);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00133f4c,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00133f4c,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00133f50), iVar5 != 0))
    goto LAB_001339f0;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_00133f74);
    pcVar6 = getenv(DAT_00133f78);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_00133f7c),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_00133f80);
    if (iVar10 == 0) {
      uVar1 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00133f80);
      uVar1 = json_object_get_int64();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_00133f84);
    if (iVar10 == 0) {
      uStack_10040 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00133f84);
      uStack_10040 = json_object_get_int64();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_00133f88);
    if (iVar10 == 0) {
      uStack_10044 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00133f88);
      uStack_10044 = json_object_get_int64();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_00133f8c);
    if (iVar10 == 0) {
      uStack_10048 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00133f8c);
      uStack_10048 = json_object_get_int64();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_00133f90);
    if (iVar10 == 0) {
      uVar8 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00133f90);
      uVar8 = json_object_get_int64();
    }
    CMD_Start_Firmware_Update(auStack_10034,uStack_10044,uVar1,uVar8,uStack_10040,uStack_10048,1);
    if (iStack_10030 == 0) {
      uVar8 = json_object_new_int(uVar1);
      json_object_object_add(iVar5,DAT_00133f80,uVar8);
      uVar8 = json_object_new_int(uStack_10040);
      json_object_object_add(iVar5,DAT_00133f84,uVar8);
      uVar8 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar5,DAT_00133f88,uVar8);
      qcgires_setcontenttype(iVar2,DAT_00133f5c);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_00133f6c,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_00133f7c);
        goto LAB_00133e08;
      }
    }
    else {
      uVar8 = json_object_new_int(uVar1);
      json_object_object_add(iVar5,DAT_00133f80,uVar8);
      uVar8 = json_object_new_int(uStack_10040);
      json_object_object_add(iVar5,DAT_00133f84,uVar8);
      uVar8 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar5,DAT_00133f88,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        iVar9 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_00133f94,0x1f);
        json_object_object_add(iVar9,DAT_00133f68,uVar8);
        uVar8 = json_object_new_int(DAT_00133f98);
        json_object_object_add(iVar9,DAT_00133f9c,uVar8);
        FCGI_printf(DAT_00133fa4,DAT_00133fa0);
        qcgires_setcontenttype(iVar2,DAT_00133f5c);
        uVar8 = json_object_to_json_string(iVar9);
        FCGI_printf(DAT_00133f6c,uVar8);
      }
      else {
        strcasecmp(pcVar3,DAT_00133f7c);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_00133f94,0x1f);
        json_object_object_add(iVar5,DAT_00133f68,uVar8);
        uVar8 = json_object_new_int(DAT_00133f98);
        json_object_object_add(iVar5,DAT_00133f9c,uVar8);
        FCGI_printf(DAT_00133fa4,DAT_00133fa0);
        qcgires_setcontenttype(iVar2,DAT_00133f5c);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00133f6c,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_00133f7c);
      }
LAB_00133e08:
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
  }
  else {
LAB_001339f0:
    FCGI_printf(DAT_00133f54);
    FCGI_printf(DAT_00133f58);
    qcgires_setcontenttype(iVar2,DAT_00133f5c);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_00133f60,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00133f50);
    uVar8 = DAT_00133f64;
    if (iVar5 == 1) {
      uVar8 = DAT_00133f70;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_00133f68,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_00133f6c,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_00133aa0:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x00133abc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

