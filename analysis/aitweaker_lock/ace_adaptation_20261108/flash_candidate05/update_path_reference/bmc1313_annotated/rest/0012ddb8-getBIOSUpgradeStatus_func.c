/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "0012e2d4": {
    "elf_va": "0x12e2d4",
    "file_offset": "0x11e2d4",
    "raw_u32": "0x148ce8",
    "target_elf_va": "0x148ce8",
    "target_string": "HTTP_X_CSRFTOKEN"
  },
  "0012e2d8": {
    "elf_va": "0x12e2d8",
    "file_offset": "0x11e2d8",
    "raw_u32": "0x150c40",
    "target_elf_va": "0x150c40",
    "target_string": "authorized"
  },
  "0012e2dc": {
    "elf_va": "0x12e2dc",
    "file_offset": "0x11e2dc",
    "raw_u32": "0x148d80",
    "target_elf_va": "0x148d80",
    "target_string": "CSRFTOKEN"
  },
  "0012e2e0": {
    "elf_va": "0x12e2e0",
    "file_offset": "0x11e2e0",
    "raw_u32": "0x148d70",
    "target_elf_va": "0x148d70",
    "target_string": "passwordStatus"
  },
  "0012e2e4": {
    "elf_va": "0x12e2e4",
    "file_offset": "0x11e2e4",
    "raw_u32": "0x148cfc",
    "target_elf_va": "0x148cfc",
    "target_string": "Status: 401 Unauthorized \n"
  },
  "0012e2e8": {
    "elf_va": "0x12e2e8",
    "file_offset": "0x11e2e8",
    "raw_u32": "0x148d18",
    "target_elf_va": "0x148d18",
    "target_string": "Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n"
  },
  "0012e2ec": {
    "elf_va": "0x12e2ec",
    "file_offset": "0x11e2ec",
    "raw_u32": "0x147aa0",
    "target_elf_va": "0x147aa0",
    "target_string": "application/json"
  },
  "0012e2f0": {
    "elf_va": "0x12e2f0",
    "file_offset": "0x11e2f0",
    "raw_u32": "0x147a78",
    "target_elf_va": "0x147a78",
    "target_string": "cc"
  },
  "0012e2f4": {
    "elf_va": "0x12e2f4",
    "file_offset": "0x11e2f4",
    "raw_u32": "0x148d58",
    "target_elf_va": "0x148d58",
    "target_string": "Invalid Authentication"
  },
  "0012e2f8": {
    "elf_va": "0x12e2f8",
    "file_offset": "0x11e2f8",
    "raw_u32": "0x1533bc",
    "target_elf_va": "0x1533bc",
    "target_string": "error"
  },
  "0012e2fc": {
    "elf_va": "0x12e2fc",
    "file_offset": "0x11e2fc",
    "raw_u32": "0x148c34",
    "target_elf_va": "0x148c34",
    "target_string": "%s"
  },
  "0012e300": {
    "elf_va": "0x12e300",
    "file_offset": "0x11e300",
    "raw_u32": "0x148d8c",
    "target_elf_va": "0x148d8c",
    "target_string": "Password should be changed for default user and should have a minimum of 8 characters."
  },
  "0012e304": {
    "elf_va": "0x12e304",
    "file_offset": "0x11e304",
    "raw_u32": "0x147268",
    "target_elf_va": "0x147268",
    "target_string": "REQUEST_METHOD"
  },
  "0012e308": {
    "elf_va": "0x12e308",
    "file_offset": "0x11e308",
    "raw_u32": "0x148de4",
    "target_elf_va": "0x148de4",
    "target_string": "CONTENT_TYPE"
  },
  "0012e30c": {
    "elf_va": "0x12e30c",
    "file_offset": "0x11e30c",
    "raw_u32": "0x148df4",
    "target_elf_va": "0x148df4",
    "target_string": "GET"
  },
  "0012e310": {
    "elf_va": "0x12e310",
    "file_offset": "0x11e310",
    "raw_u32": "0x150fc4",
    "target_elf_va": "0x150fc4",
    "target_string": "COMPONENT_ID"
  },
  "0012e314": {
    "elf_va": "0x12e314",
    "file_offset": "0x11e314",
    "raw_u32": "0x1510c8",
    "target_elf_va": "0x1510c8",
    "target_string": "PROGRESS"
  },
  "0012e318": {
    "elf_va": "0x12e318",
    "file_offset": "0x11e318",
    "raw_u32": "0x1565fc",
    "target_elf_va": "0x1565fc",
    "target_string": "Error in Finish Firmware Upload"
  },
  "0012e31c": {
    "elf_va": "0x12e31c",
    "file_offset": "0x11e31c",
    "raw_u32": "0x55d",
    "target_elf_va": "0x55d"
  },
  "0012e320": {
    "elf_va": "0x12e320",
    "file_offset": "0x11e320",
    "raw_u32": "0x148e24",
    "target_elf_va": "0x148e24",
    "target_string": "code"
  },
  "0012e324": {
    "elf_va": "0x12e324",
    "file_offset": "0x11e324",
    "raw_u32": "0x148e78",
    "target_elf_va": "0x148e78",
    "target_string": "500 Internal Server Error"
  },
  "0012e328": {
    "elf_va": "0x12e328",
    "file_offset": "0x11e328",
    "raw_u32": "0x148e40",
    "target_elf_va": "0x148e40",
    "target_string": "Status: %s \n"
  }
}
*/

void getBIOSUpgradeStatus_func(void)

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
  pcVar2 = getenv(DAT_0012e2d4);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_0012e2e4);
    FCGI_printf(DAT_0012e2e8);
    qcgires_setcontenttype(iVar1,DAT_0012e2ec);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0012e2f0,uVar6);
    uVar6 = json_object_new_string(DAT_0012e2f4);
    json_object_object_add(uVar7,DAT_0012e2f8,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0012e2fc,uVar6);
    json_object_put(uVar7);
    goto LAB_0012df34;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012e2d8);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0012e2dc,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0012e2dc,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012e2e0), iVar4 != 0))
    goto LAB_0012de84;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_0012e304);
    pcVar5 = getenv(DAT_0012e308);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_0012e30c),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    pcVar5 = (char *)(**(code **)(iVar1 + 0x18))(iVar1,DAT_0012e310,0);
    snprintf(acStack_10040,10,DAT_0012e2fc,pcVar5);
    uVar10 = strtol(pcVar5,(char **)0x0,10);
    uVar10 = uVar10 & 0xff;
    CMD_Get_Firmware_Progress(auStack_10034,uVar10,1,&uStack_10044,1);
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,DAT_0012e310,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,DAT_0012e314,uVar7);
      qcgires_setcontenttype(iVar1,DAT_0012e2ec);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_0012e2fc,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_0012e30c);
LAB_0012e1b8:
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
      }
    }
    else {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,DAT_0012e310,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,DAT_0012e314,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_0012e30c);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_0012e318,0x1f);
        json_object_object_add(iVar4,DAT_0012e2f8,uVar7);
        uVar7 = json_object_new_int(DAT_0012e31c);
        json_object_object_add(iVar4,DAT_0012e320,uVar7);
        FCGI_printf(DAT_0012e328,DAT_0012e324);
        qcgires_setcontenttype(iVar1,DAT_0012e2ec);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_0012e2fc,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_0012e30c);
        goto LAB_0012e1b8;
      }
      iVar4 = json_object_new_object();
      uVar7 = json_object_new_string_len(DAT_0012e318,0x1f);
      json_object_object_add(iVar4,DAT_0012e2f8,uVar7);
      uVar7 = json_object_new_int(DAT_0012e31c);
      json_object_object_add(iVar4,DAT_0012e320,uVar7);
      FCGI_printf(DAT_0012e328,DAT_0012e324);
      qcgires_setcontenttype(iVar1,DAT_0012e2ec);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_0012e2fc,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
    }
  }
  else {
LAB_0012de84:
    FCGI_printf(DAT_0012e2e4);
    FCGI_printf(DAT_0012e2e8);
    qcgires_setcontenttype(iVar1,DAT_0012e2ec);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_0012e2f0,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012e2e0);
    uVar7 = DAT_0012e2f4;
    if (iVar4 == 1) {
      uVar7 = DAT_0012e300;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_0012e2f8,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_0012e2fc,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_0012df34:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

