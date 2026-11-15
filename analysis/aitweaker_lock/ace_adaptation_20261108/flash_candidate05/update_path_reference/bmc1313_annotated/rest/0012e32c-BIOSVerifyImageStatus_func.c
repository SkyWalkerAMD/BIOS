/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "0012e84c": {
    "elf_va": "0x12e84c",
    "file_offset": "0x11e84c",
    "raw_u32": "0x148ce8",
    "target_elf_va": "0x148ce8",
    "target_string": "HTTP_X_CSRFTOKEN"
  },
  "0012e850": {
    "elf_va": "0x12e850",
    "file_offset": "0x11e850",
    "raw_u32": "0x150c40",
    "target_elf_va": "0x150c40",
    "target_string": "authorized"
  },
  "0012e854": {
    "elf_va": "0x12e854",
    "file_offset": "0x11e854",
    "raw_u32": "0x148d80",
    "target_elf_va": "0x148d80",
    "target_string": "CSRFTOKEN"
  },
  "0012e858": {
    "elf_va": "0x12e858",
    "file_offset": "0x11e858",
    "raw_u32": "0x148d70",
    "target_elf_va": "0x148d70",
    "target_string": "passwordStatus"
  },
  "0012e85c": {
    "elf_va": "0x12e85c",
    "file_offset": "0x11e85c",
    "raw_u32": "0x148cfc",
    "target_elf_va": "0x148cfc",
    "target_string": "Status: 401 Unauthorized \n"
  },
  "0012e860": {
    "elf_va": "0x12e860",
    "file_offset": "0x11e860",
    "raw_u32": "0x148d18",
    "target_elf_va": "0x148d18",
    "target_string": "Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n"
  },
  "0012e864": {
    "elf_va": "0x12e864",
    "file_offset": "0x11e864",
    "raw_u32": "0x147aa0",
    "target_elf_va": "0x147aa0",
    "target_string": "application/json"
  },
  "0012e868": {
    "elf_va": "0x12e868",
    "file_offset": "0x11e868",
    "raw_u32": "0x147a78",
    "target_elf_va": "0x147a78",
    "target_string": "cc"
  },
  "0012e86c": {
    "elf_va": "0x12e86c",
    "file_offset": "0x11e86c",
    "raw_u32": "0x148d58",
    "target_elf_va": "0x148d58",
    "target_string": "Invalid Authentication"
  },
  "0012e870": {
    "elf_va": "0x12e870",
    "file_offset": "0x11e870",
    "raw_u32": "0x1533bc",
    "target_elf_va": "0x1533bc",
    "target_string": "error"
  },
  "0012e874": {
    "elf_va": "0x12e874",
    "file_offset": "0x11e874",
    "raw_u32": "0x148c34",
    "target_elf_va": "0x148c34",
    "target_string": "%s"
  },
  "0012e878": {
    "elf_va": "0x12e878",
    "file_offset": "0x11e878",
    "raw_u32": "0x148d8c",
    "target_elf_va": "0x148d8c",
    "target_string": "Password should be changed for default user and should have a minimum of 8 characters."
  },
  "0012e87c": {
    "elf_va": "0x12e87c",
    "file_offset": "0x11e87c",
    "raw_u32": "0x147268",
    "target_elf_va": "0x147268",
    "target_string": "REQUEST_METHOD"
  },
  "0012e880": {
    "elf_va": "0x12e880",
    "file_offset": "0x11e880",
    "raw_u32": "0x148de4",
    "target_elf_va": "0x148de4",
    "target_string": "CONTENT_TYPE"
  },
  "0012e884": {
    "elf_va": "0x12e884",
    "file_offset": "0x11e884",
    "raw_u32": "0x148df4",
    "target_elf_va": "0x148df4",
    "target_string": "GET"
  },
  "0012e888": {
    "elf_va": "0x12e888",
    "file_offset": "0x11e888",
    "raw_u32": "0x150fc4",
    "target_elf_va": "0x150fc4",
    "target_string": "COMPONENT_ID"
  },
  "0012e88c": {
    "elf_va": "0x12e88c",
    "file_offset": "0x11e88c",
    "raw_u32": "0x1510c8",
    "target_elf_va": "0x1510c8",
    "target_string": "PROGRESS"
  },
  "0012e890": {
    "elf_va": "0x12e890",
    "file_offset": "0x11e890",
    "raw_u32": "0x1565fc",
    "target_elf_va": "0x1565fc",
    "target_string": "Error in Finish Firmware Upload"
  },
  "0012e894": {
    "elf_va": "0x12e894",
    "file_offset": "0x11e894",
    "raw_u32": "0x55d",
    "target_elf_va": "0x55d"
  },
  "0012e898": {
    "elf_va": "0x12e898",
    "file_offset": "0x11e898",
    "raw_u32": "0x148e24",
    "target_elf_va": "0x148e24",
    "target_string": "code"
  },
  "0012e89c": {
    "elf_va": "0x12e89c",
    "file_offset": "0x11e89c",
    "raw_u32": "0x148e78",
    "target_elf_va": "0x148e78",
    "target_string": "500 Internal Server Error"
  },
  "0012e8a0": {
    "elf_va": "0x12e8a0",
    "file_offset": "0x11e8a0",
    "raw_u32": "0x148e40",
    "target_elf_va": "0x148e40",
    "target_string": "Status: %s \n"
  }
}
*/

void BIOSVerifyImageStatus_func(void)

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
  uint uVar10;
  undefined4 uStack_10044;
  char acStack_10040 [12];
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_0012e84c);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_0012e85c);
    FCGI_printf(DAT_0012e860);
    qcgires_setcontenttype(iVar1,DAT_0012e864);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0012e868,uVar6);
    uVar6 = json_object_new_string(DAT_0012e86c);
    json_object_object_add(uVar7,DAT_0012e870,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0012e874,uVar6);
    json_object_put(uVar7);
    goto LAB_0012e4a8;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012e850);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0012e854,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0012e854,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012e858), iVar4 != 0))
    goto LAB_0012e3f8;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_0012e87c);
    pcVar5 = getenv(DAT_0012e880);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_0012e884),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    pcVar5 = (char *)(**(code **)(iVar1 + 0x18))(iVar1,DAT_0012e888,0);
    snprintf(acStack_10040,10,DAT_0012e874,pcVar5);
    uVar10 = strtol(pcVar5,(char **)0x0,10);
    uVar10 = uVar10 & 0xff;
    CMD_Get_Firmware_Progress(auStack_10034,uVar10,2,&uStack_10044,1);
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,DAT_0012e888,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,DAT_0012e88c,uVar7);
      qcgires_setcontenttype(iVar1,DAT_0012e864);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_0012e874,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_0012e884);
LAB_0012e730:
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
      }
    }
    else {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,DAT_0012e888,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,DAT_0012e88c,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_0012e884);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_0012e890,0x1f);
        json_object_object_add(iVar4,DAT_0012e870,uVar7);
        uVar7 = json_object_new_int(DAT_0012e894);
        json_object_object_add(iVar4,DAT_0012e898,uVar7);
        FCGI_printf(DAT_0012e8a0,DAT_0012e89c);
        qcgires_setcontenttype(iVar1,DAT_0012e864);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_0012e874,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_0012e884);
        goto LAB_0012e730;
      }
      iVar4 = json_object_new_object();
      uVar7 = json_object_new_string_len(DAT_0012e890,0x1f);
      json_object_object_add(iVar4,DAT_0012e870,uVar7);
      uVar7 = json_object_new_int(DAT_0012e894);
      json_object_object_add(iVar4,DAT_0012e898,uVar7);
      FCGI_printf(DAT_0012e8a0,DAT_0012e89c);
      qcgires_setcontenttype(iVar1,DAT_0012e864);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_0012e874,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
    }
  }
  else {
LAB_0012e3f8:
    FCGI_printf(DAT_0012e85c);
    FCGI_printf(DAT_0012e860);
    qcgires_setcontenttype(iVar1,DAT_0012e864);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_0012e868,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012e858);
    uVar7 = DAT_0012e86c;
    if (iVar4 == 1) {
      uVar7 = DAT_0012e878;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_0012e870,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_0012e874,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_0012e4a8:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

