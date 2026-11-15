
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
  pcVar2 = getenv(DAT_001319c0);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_001319d0);
    FCGI_printf(DAT_001319d4);
    qcgires_setcontenttype(iVar1,DAT_001319d8);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_001319dc,uVar6);
    uVar6 = json_object_new_string(DAT_001319e0);
    json_object_object_add(uVar7,DAT_001319e4,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_001319e8,uVar6);
    json_object_put(uVar7);
    goto LAB_001316a4;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_001319c4);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_001319c8,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_001319c8,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_001319cc), iVar4 != 0))
    goto LAB_001315f4;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_001319f0);
    pcVar5 = getenv(DAT_001319f4);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_001319f8),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    CMD_Enter_FW_Update_mode(auStack_10034);
    memcpy(&uStack_10038,auStack_1002a,4);
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(uStack_10038);
      json_object_object_add(iVar4,DAT_00131a10,uVar7);
      qcgires_setcontenttype(iVar1,DAT_001319d8);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_001319e8,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_001319f8);
        goto LAB_00131834;
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
        uVar7 = json_object_new_string_len(DAT_001319fc,0x20);
        json_object_object_add(iVar4,DAT_001319e4,uVar7);
        uVar7 = json_object_new_int(DAT_00131a00);
        json_object_object_add(iVar4,DAT_00131a04,uVar7);
        FCGI_printf(DAT_00131a0c,DAT_00131a08);
        qcgires_setcontenttype(iVar1,DAT_001319d8);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_001319e8,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        strcasecmp(pcVar2,DAT_001319f8);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_001319fc,0x20);
        json_object_object_add(iVar4,DAT_001319e4,uVar7);
        uVar7 = json_object_new_int(DAT_00131a00);
        json_object_object_add(iVar4,DAT_00131a04,uVar7);
        FCGI_printf(DAT_00131a0c,DAT_00131a08);
        qcgires_setcontenttype(iVar1,DAT_001319d8);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_001319e8,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_001319f8);
LAB_00131834:
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
      }
    }
  }
  else {
LAB_001315f4:
    FCGI_printf(DAT_001319d0);
    FCGI_printf(DAT_001319d4);
    qcgires_setcontenttype(iVar1,DAT_001319d8);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_001319dc,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_001319cc);
    uVar7 = DAT_001319e0;
    if (iVar4 == 1) {
      uVar7 = DAT_001319ec;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_001319e4,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_001319e8,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_001316a4:
  post_call_hook(iVar1);
                    /* WARNING: Could not recover jumptable at 0x001316c0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

