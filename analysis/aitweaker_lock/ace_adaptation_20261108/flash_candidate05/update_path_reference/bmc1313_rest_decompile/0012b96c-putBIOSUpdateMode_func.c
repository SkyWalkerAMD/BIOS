
void putBIOSUpdateMode_func(void)

{
  int iVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  char *__s;
  size_t __n;
  undefined4 uVar6;
  undefined4 uVar7;
  void *__ptr;
  int iVar8;
  int iVar9;
  undefined4 uStack_10038;
  undefined1 auStack_10034 [4];
  int iStack_10030;
  undefined1 auStack_1002a [65542];
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_0012be04);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_0012be14);
    FCGI_printf(DAT_0012be18);
    qcgires_setcontenttype(iVar1,DAT_0012be1c);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0012be20,uVar6);
    uVar6 = json_object_new_string(DAT_0012be24);
    json_object_object_add(uVar7,DAT_0012be28,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0012be2c,uVar6);
    json_object_put(uVar7);
    goto LAB_0012bae8;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012be08);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0012be0c,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0012be0c,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012be10), iVar4 != 0))
    goto LAB_0012ba38;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_0012be34);
    pcVar5 = getenv(DAT_0012be38);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_0012be3c),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    CMD_Enter_FW_Update_mode(auStack_10034);
    memcpy(&uStack_10038,auStack_1002a,4);
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(uStack_10038);
      json_object_object_add(iVar4,DAT_0012be54,uVar7);
      qcgires_setcontenttype(iVar1,DAT_0012be1c);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_0012be2c,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_0012be3c);
        goto LAB_0012bc78;
      }
    }
    else {
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 == (char *)0x0) {
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_0012be40,0x20);
        json_object_object_add(iVar4,DAT_0012be28,uVar7);
        uVar7 = json_object_new_int(DAT_0012be44);
        json_object_object_add(iVar4,DAT_0012be48,uVar7);
        FCGI_printf(DAT_0012be50,DAT_0012be4c);
        qcgires_setcontenttype(iVar1,DAT_0012be1c);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_0012be2c,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        strcasecmp(pcVar2,DAT_0012be3c);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_0012be40,0x20);
        json_object_object_add(iVar4,DAT_0012be28,uVar7);
        uVar7 = json_object_new_int(DAT_0012be44);
        json_object_object_add(iVar4,DAT_0012be48,uVar7);
        FCGI_printf(DAT_0012be50,DAT_0012be4c);
        qcgires_setcontenttype(iVar1,DAT_0012be1c);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_0012be2c,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_0012be3c);
LAB_0012bc78:
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
      }
    }
  }
  else {
LAB_0012ba38:
    FCGI_printf(DAT_0012be14);
    FCGI_printf(DAT_0012be18);
    qcgires_setcontenttype(iVar1,DAT_0012be1c);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_0012be20,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012be10);
    uVar7 = DAT_0012be24;
    if (iVar4 == 1) {
      uVar7 = DAT_0012be30;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_0012be28,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_0012be2c,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_0012bae8:
  post_call_hook(iVar1);
                    /* WARNING: Could not recover jumptable at 0x0012bb04. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

