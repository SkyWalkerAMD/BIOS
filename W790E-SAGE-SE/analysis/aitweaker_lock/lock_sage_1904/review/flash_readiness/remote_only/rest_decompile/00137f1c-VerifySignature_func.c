
void VerifySignature_func(void)

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
  undefined1 auStack_1002c [4];
  int iStack_10028;
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_00138388);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_00138398);
    FCGI_printf(DAT_0013839c);
    qcgires_setcontenttype(iVar1,DAT_001383a0);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_001383a4,uVar6);
    uVar6 = json_object_new_string(DAT_001383a8);
    json_object_object_add(uVar7,DAT_001383ac,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_001383b0,uVar6);
    json_object_put(uVar7);
    goto LAB_00138098;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0013838c);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_00138390,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_00138390,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_00138394), iVar4 != 0))
    goto LAB_00137fe8;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_001383b8);
    pcVar5 = getenv(DAT_001383bc);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_001383c0),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    CMD_Verify_BIOS_Signature(auStack_1002c);
    if (iStack_10028 == 0) {
      qcgires_setcontenttype(iVar1,DAT_001383a0);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_001383b0,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_001383c0);
        goto LAB_00138214;
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
        uVar7 = json_object_new_string_len(DAT_001383c4,0x20);
        json_object_object_add(iVar4,DAT_001383ac,uVar7);
        uVar7 = json_object_new_int(DAT_001383c8);
        json_object_object_add(iVar4,DAT_001383cc,uVar7);
        FCGI_printf(DAT_001383d4,DAT_001383d0);
        qcgires_setcontenttype(iVar1,DAT_001383a0);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_001383b0,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        strcasecmp(pcVar2,DAT_001383c0);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_001383c4,0x20);
        json_object_object_add(iVar4,DAT_001383ac,uVar7);
        uVar7 = json_object_new_int(DAT_001383c8);
        json_object_object_add(iVar4,DAT_001383cc,uVar7);
        FCGI_printf(DAT_001383d4,DAT_001383d0);
        qcgires_setcontenttype(iVar1,DAT_001383a0);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_001383b0,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_001383c0);
LAB_00138214:
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
      }
    }
  }
  else {
LAB_00137fe8:
    FCGI_printf(DAT_00138398);
    FCGI_printf(DAT_0013839c);
    qcgires_setcontenttype(iVar1,DAT_001383a0);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_001383a4,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_00138394);
    uVar7 = DAT_001383a8;
    if (iVar4 == 1) {
      uVar7 = DAT_001383b4;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_001383ac,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_001383b0,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_00138098:
  post_call_hook(iVar1);
                    /* WARNING: Could not recover jumptable at 0x001380b4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

