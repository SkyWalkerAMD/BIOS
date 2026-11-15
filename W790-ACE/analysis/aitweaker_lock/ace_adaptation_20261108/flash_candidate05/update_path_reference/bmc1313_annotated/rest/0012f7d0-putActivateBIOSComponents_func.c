/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "0012fc94": {
    "elf_va": "0x12fc94",
    "file_offset": "0x11fc94",
    "raw_u32": "0x148ce8",
    "target_elf_va": "0x148ce8",
    "target_string": "HTTP_X_CSRFTOKEN"
  },
  "0012fc98": {
    "elf_va": "0x12fc98",
    "file_offset": "0x11fc98",
    "raw_u32": "0x150c40",
    "target_elf_va": "0x150c40",
    "target_string": "authorized"
  },
  "0012fc9c": {
    "elf_va": "0x12fc9c",
    "file_offset": "0x11fc9c",
    "raw_u32": "0x148d80",
    "target_elf_va": "0x148d80",
    "target_string": "CSRFTOKEN"
  },
  "0012fca0": {
    "elf_va": "0x12fca0",
    "file_offset": "0x11fca0",
    "raw_u32": "0x148d70",
    "target_elf_va": "0x148d70",
    "target_string": "passwordStatus"
  },
  "0012fca4": {
    "elf_va": "0x12fca4",
    "file_offset": "0x11fca4",
    "raw_u32": "0x148cfc",
    "target_elf_va": "0x148cfc",
    "target_string": "Status: 401 Unauthorized \n"
  },
  "0012fca8": {
    "elf_va": "0x12fca8",
    "file_offset": "0x11fca8",
    "raw_u32": "0x148d18",
    "target_elf_va": "0x148d18",
    "target_string": "Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n"
  },
  "0012fcac": {
    "elf_va": "0x12fcac",
    "file_offset": "0x11fcac",
    "raw_u32": "0x147aa0",
    "target_elf_va": "0x147aa0",
    "target_string": "application/json"
  },
  "0012fcb0": {
    "elf_va": "0x12fcb0",
    "file_offset": "0x11fcb0",
    "raw_u32": "0x147a78",
    "target_elf_va": "0x147a78",
    "target_string": "cc"
  },
  "0012fcb4": {
    "elf_va": "0x12fcb4",
    "file_offset": "0x11fcb4",
    "raw_u32": "0x148d58",
    "target_elf_va": "0x148d58",
    "target_string": "Invalid Authentication"
  },
  "0012fcb8": {
    "elf_va": "0x12fcb8",
    "file_offset": "0x11fcb8",
    "raw_u32": "0x1533bc",
    "target_elf_va": "0x1533bc",
    "target_string": "error"
  },
  "0012fcbc": {
    "elf_va": "0x12fcbc",
    "file_offset": "0x11fcbc",
    "raw_u32": "0x148c34",
    "target_elf_va": "0x148c34",
    "target_string": "%s"
  },
  "0012fcc0": {
    "elf_va": "0x12fcc0",
    "file_offset": "0x11fcc0",
    "raw_u32": "0x148d8c",
    "target_elf_va": "0x148d8c",
    "target_string": "Password should be changed for default user and should have a minimum of 8 characters."
  },
  "0012fcc4": {
    "elf_va": "0x12fcc4",
    "file_offset": "0x11fcc4",
    "raw_u32": "0x147268",
    "target_elf_va": "0x147268",
    "target_string": "REQUEST_METHOD"
  },
  "0012fcc8": {
    "elf_va": "0x12fcc8",
    "file_offset": "0x11fcc8",
    "raw_u32": "0x148de4",
    "target_elf_va": "0x148de4",
    "target_string": "CONTENT_TYPE"
  },
  "0012fccc": {
    "elf_va": "0x12fccc",
    "file_offset": "0x11fccc",
    "raw_u32": "0x148df4",
    "target_elf_va": "0x148df4",
    "target_string": "GET"
  },
  "0012fcd0": {
    "elf_va": "0x12fcd0",
    "file_offset": "0x11fcd0",
    "raw_u32": "0x150fc4",
    "target_elf_va": "0x150fc4",
    "target_string": "COMPONENT_ID"
  },
  "0012fcd4": {
    "elf_va": "0x12fcd4",
    "file_offset": "0x11fcd4",
    "raw_u32": "0x1565fc",
    "target_elf_va": "0x1565fc",
    "target_string": "Error in Finish Firmware Upload"
  },
  "0012fcd8": {
    "elf_va": "0x12fcd8",
    "file_offset": "0x11fcd8",
    "raw_u32": "0x55d",
    "target_elf_va": "0x55d"
  },
  "0012fcdc": {
    "elf_va": "0x12fcdc",
    "file_offset": "0x11fcdc",
    "raw_u32": "0x148e24",
    "target_elf_va": "0x148e24",
    "target_string": "code"
  },
  "0012fce0": {
    "elf_va": "0x12fce0",
    "file_offset": "0x11fce0",
    "raw_u32": "0x148e78",
    "target_elf_va": "0x148e78",
    "target_string": "500 Internal Server Error"
  },
  "0012fce4": {
    "elf_va": "0x12fce4",
    "file_offset": "0x11fce4",
    "raw_u32": "0x148e40",
    "target_elf_va": "0x148e40",
    "target_string": "Status: %s \n"
  }
}
*/

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

