
void getFlashProgress_func(void)

{
  int iVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  char *__s;
  size_t sVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  void *__ptr;
  int iVar9;
  int iVar10;
  undefined1 auStack_84 [3];
  char acStack_81 [60];
  char acStack_45 [29];
  uint local_28;
  byte local_24;
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_000e5824);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_000e5834);
    FCGI_printf(DAT_000e5838);
    qcgires_setcontenttype(iVar1,DAT_000e583c);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_000e5840,uVar7);
    uVar7 = json_object_new_string(DAT_000e5844);
    json_object_object_add(uVar8,DAT_000e5848,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_000e584c,uVar7);
    json_object_put(uVar8);
    goto LAB_000e549c;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e5828);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000e582c,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000e582c,0);
    sVar6 = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,sVar6);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e5830), iVar4 != 0))
    goto LAB_000e53ec;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar9 = json_object_new_object();
    pcVar2 = getenv(DAT_000e5854);
    pcVar5 = getenv(DAT_000e5858);
    if ((pcVar2 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar2,DAT_000e585c),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    iVar10 = GetFlashProgress(auStack_84);
    if (iVar10 == 0xff) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000e587c,DAT_000e5878,DAT_000e5874);
LAB_000e56a4:
      uVar8 = json_object_new_int(1);
      json_object_object_add(iVar4,DAT_000e5880,uVar8);
      sVar6 = strlen(acStack_81);
      uVar8 = json_object_new_string_len(acStack_81,sVar6);
      json_object_object_add(iVar4,DAT_000e5884,uVar8);
      sVar6 = strlen(acStack_45);
      uVar8 = json_object_new_string_len(acStack_45,sVar6);
      json_object_object_add(iVar4,DAT_000e5888,uVar8);
      uVar8 = json_object_new_int((uint)local_24 << 0x18 | local_28 >> 8);
      json_object_object_add(iVar4,DAT_000e588c,uVar8);
      qcgires_setcontenttype(iVar1,DAT_000e583c);
      uVar8 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000e584c,uVar8);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_000e585c);
LAB_000e577c:
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
      }
    }
    else {
      if (iVar10 == 0) goto LAB_000e56a4;
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_000e585c);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar4 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000e5860,0x26);
        json_object_object_add(iVar4,DAT_000e5848,uVar8);
        uVar8 = json_object_new_int(DAT_000e5864);
        json_object_object_add(iVar4,DAT_000e5868,uVar8);
        FCGI_printf(DAT_000e5870,DAT_000e586c);
        qcgires_setcontenttype(iVar1,DAT_000e583c);
        uVar8 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_000e584c,uVar8);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_000e585c);
        goto LAB_000e577c;
      }
      iVar4 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000e5860,0x26);
      json_object_object_add(iVar4,DAT_000e5848,uVar8);
      uVar8 = json_object_new_int(DAT_000e5864);
      json_object_object_add(iVar4,DAT_000e5868,uVar8);
      FCGI_printf(DAT_000e5870,DAT_000e586c);
      qcgires_setcontenttype(iVar1,DAT_000e583c);
      uVar8 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000e584c,uVar8);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
    }
  }
  else {
LAB_000e53ec:
    FCGI_printf(DAT_000e5834);
    FCGI_printf(DAT_000e5838);
    qcgires_setcontenttype(iVar1,DAT_000e583c);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_000e5840,uVar8);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e5830);
    uVar8 = DAT_000e5844;
    if (iVar4 == 1) {
      uVar8 = DAT_000e5850;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_000e5848,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_000e584c,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_000e549c:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

