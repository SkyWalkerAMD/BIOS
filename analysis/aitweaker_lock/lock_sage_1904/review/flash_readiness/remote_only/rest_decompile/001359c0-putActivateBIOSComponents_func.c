
void putActivateBIOSComponents_func(void)

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
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_00135e84);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00135e94);
    FCGI_printf(DAT_00135e98);
    qcgires_setcontenttype(iVar2,DAT_00135e9c);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_00135ea0,uVar7);
    uVar7 = json_object_new_string(DAT_00135ea4);
    json_object_object_add(uVar8,DAT_00135ea8,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_00135eac,uVar7);
    json_object_put(uVar8);
    goto LAB_00135b3c;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00135e88);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00135e8c,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00135e8c,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00135e90), iVar5 != 0))
    goto LAB_00135a8c;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_00135eb4);
    pcVar6 = getenv(DAT_00135eb8);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_00135ebc),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_00135ec0);
    if (iVar10 == 0) {
      uVar1 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00135ec0);
      uVar1 = json_object_get_int64();
    }
    CMD_Activate_Firmware_Image(auStack_10034,uVar1,1);
    uVar8 = json_object_new_int(uVar1);
    json_object_object_add(iVar5,DAT_00135ec0,uVar8);
    if (iStack_10030 == 0) {
      qcgires_setcontenttype(iVar2,DAT_00135e9c);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_00135eac,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_00135ebc);
        goto LAB_00135d10;
      }
    }
    else {
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_00135ec4,0x1f);
        json_object_object_add(iVar5,DAT_00135ea8,uVar8);
        uVar8 = json_object_new_int(DAT_00135ec8);
        json_object_object_add(iVar5,DAT_00135ecc,uVar8);
        FCGI_printf(DAT_00135ed4,DAT_00135ed0);
        qcgires_setcontenttype(iVar2,DAT_00135e9c);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00135eac,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
      }
      else {
        strcasecmp(pcVar3,DAT_00135ebc);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_00135ec4,0x1f);
        json_object_object_add(iVar5,DAT_00135ea8,uVar8);
        uVar8 = json_object_new_int(DAT_00135ec8);
        json_object_object_add(iVar5,DAT_00135ecc,uVar8);
        FCGI_printf(DAT_00135ed4,DAT_00135ed0);
        qcgires_setcontenttype(iVar2,DAT_00135e9c);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00135eac,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_00135ebc);
LAB_00135d10:
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
      }
    }
  }
  else {
LAB_00135a8c:
    FCGI_printf(DAT_00135e94);
    FCGI_printf(DAT_00135e98);
    qcgires_setcontenttype(iVar2,DAT_00135e9c);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_00135ea0,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00135e90);
    uVar8 = DAT_00135ea4;
    if (iVar5 == 1) {
      uVar8 = DAT_00135eb0;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_00135ea8,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_00135eac,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_00135b3c:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x00135b58. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

