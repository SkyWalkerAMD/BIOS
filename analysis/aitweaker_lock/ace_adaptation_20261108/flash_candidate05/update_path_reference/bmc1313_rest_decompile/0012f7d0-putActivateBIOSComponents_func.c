
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
  pcVar3 = getenv(DAT_0012fc94);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0012fca4);
    FCGI_printf(DAT_0012fca8);
    qcgires_setcontenttype(iVar2,DAT_0012fcac);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_0012fcb0,uVar7);
    uVar7 = json_object_new_string(DAT_0012fcb4);
    json_object_object_add(uVar8,DAT_0012fcb8,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0012fcbc,uVar7);
    json_object_put(uVar8);
    goto LAB_0012f94c;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012fc98);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012fc9c,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012fc9c,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012fca0), iVar5 != 0))
    goto LAB_0012f89c;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_0012fcc4);
    pcVar6 = getenv(DAT_0012fcc8);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_0012fccc),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    iVar10 = json_object_object_get_rest(iVar9,DAT_0012fcd0);
    if (iVar10 == 0) {
      uVar1 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_0012fcd0);
      uVar1 = json_object_get_int();
    }
    CMD_Activate_Firmware_Image(auStack_10034,uVar1,1);
    uVar8 = json_object_new_int(uVar1);
    json_object_object_add(iVar5,DAT_0012fcd0,uVar8);
    if (iStack_10030 == 0) {
      qcgires_setcontenttype(iVar2,DAT_0012fcac);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0012fcbc,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0012fccc);
        goto LAB_0012fb20;
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
        uVar8 = json_object_new_string_len(DAT_0012fcd4,0x1f);
        json_object_object_add(iVar5,DAT_0012fcb8,uVar8);
        uVar8 = json_object_new_int(DAT_0012fcd8);
        json_object_object_add(iVar5,DAT_0012fcdc,uVar8);
        FCGI_printf(DAT_0012fce4,DAT_0012fce0);
        qcgires_setcontenttype(iVar2,DAT_0012fcac);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0012fcbc,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
      }
      else {
        strcasecmp(pcVar3,DAT_0012fccc);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0012fcd4,0x1f);
        json_object_object_add(iVar5,DAT_0012fcb8,uVar8);
        uVar8 = json_object_new_int(DAT_0012fcd8);
        json_object_object_add(iVar5,DAT_0012fcdc,uVar8);
        FCGI_printf(DAT_0012fce4,DAT_0012fce0);
        qcgires_setcontenttype(iVar2,DAT_0012fcac);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0012fcbc,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_0012fccc);
LAB_0012fb20:
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
      }
    }
  }
  else {
LAB_0012f89c:
    FCGI_printf(DAT_0012fca4);
    FCGI_printf(DAT_0012fca8);
    qcgires_setcontenttype(iVar2,DAT_0012fcac);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0012fcb0,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012fca0);
    uVar8 = DAT_0012fcb4;
    if (iVar5 == 1) {
      uVar8 = DAT_0012fcc0;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_0012fcb8,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0012fcbc,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0012f94c:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x0012f968. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

