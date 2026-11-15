
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
  pcVar3 = getenv(DAT_0012ee08);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0012ee18);
    FCGI_printf(DAT_0012ee1c);
    qcgires_setcontenttype(iVar2,DAT_0012ee20);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_0012ee24,uVar7);
    uVar7 = json_object_new_string(DAT_0012ee28);
    json_object_object_add(uVar8,DAT_0012ee2c,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0012ee30,uVar7);
    json_object_put(uVar8);
    goto LAB_0012ea20;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012ee0c);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012ee10,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012ee10,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012ee14), iVar5 != 0))
    goto LAB_0012e970;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_0012ee38);
    pcVar6 = getenv(DAT_0012ee3c);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_0012ee40),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_0012ee44);
    if (iVar10 == 0) {
      uVar1 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012ee44);
      uVar1 = json_object_get_int();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_0012ee48);
    if (iVar10 == 0) {
      uStack_10040 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012ee48);
      uStack_10040 = json_object_get_int();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_0012ee4c);
    if (iVar10 == 0) {
      uStack_1003c = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012ee4c);
      uStack_1003c = json_object_get_int();
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_0012ee50);
    if (iVar10 == 0) {
      uVar8 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012ee50);
      uVar8 = json_object_get_int();
    }
    CMD_Verify_Firmware_Update(auStack_10034,uStack_1003c,uVar1,uVar8,uStack_10040,1);
    if (iStack_10030 == 0) {
      uVar8 = json_object_new_int(uVar1);
      json_object_object_add(iVar5,DAT_0012ee44,uVar8);
      qcgires_setcontenttype(iVar2,DAT_0012ee20);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0012ee30,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0012ee40);
        goto LAB_0012ecfc;
      }
    }
    else {
      uVar8 = json_object_new_int(uVar1);
      json_object_object_add(iVar5,DAT_0012ee44,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        iVar9 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0012ee54,0x1f);
        json_object_object_add(iVar9,DAT_0012ee2c,uVar8);
        uVar8 = json_object_new_int(DAT_0012ee58);
        json_object_object_add(iVar9,DAT_0012ee5c,uVar8);
        FCGI_printf(DAT_0012ee64,DAT_0012ee60);
        qcgires_setcontenttype(iVar2,DAT_0012ee20);
        uVar8 = json_object_to_json_string(iVar9);
        FCGI_printf(DAT_0012ee30,uVar8);
      }
      else {
        strcasecmp(pcVar3,DAT_0012ee40);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0012ee54,0x1f);
        json_object_object_add(iVar5,DAT_0012ee2c,uVar8);
        uVar8 = json_object_new_int(DAT_0012ee58);
        json_object_object_add(iVar5,DAT_0012ee5c,uVar8);
        FCGI_printf(DAT_0012ee64,DAT_0012ee60);
        qcgires_setcontenttype(iVar2,DAT_0012ee20);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0012ee30,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_0012ee40);
      }
LAB_0012ecfc:
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
  }
  else {
LAB_0012e970:
    FCGI_printf(DAT_0012ee18);
    FCGI_printf(DAT_0012ee1c);
    qcgires_setcontenttype(iVar2,DAT_0012ee20);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0012ee24,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012ee14);
    uVar8 = DAT_0012ee28;
    if (iVar5 == 1) {
      uVar8 = DAT_0012ee34;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_0012ee2c,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0012ee30,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0012ea20:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x0012ea3c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

