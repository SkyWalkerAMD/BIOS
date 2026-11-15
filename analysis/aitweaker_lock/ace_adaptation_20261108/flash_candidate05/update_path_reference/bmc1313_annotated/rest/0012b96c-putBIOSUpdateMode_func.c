/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "0012be04": {
    "elf_va": "0x12be04",
    "file_offset": "0x11be04",
    "raw_u32": "0x148ce8",
    "target_elf_va": "0x148ce8",
    "target_string": "HTTP_X_CSRFTOKEN"
  },
  "0012be08": {
    "elf_va": "0x12be08",
    "file_offset": "0x11be08",
    "raw_u32": "0x150c40",
    "target_elf_va": "0x150c40",
    "target_string": "authorized"
  },
  "0012be0c": {
    "elf_va": "0x12be0c",
    "file_offset": "0x11be0c",
    "raw_u32": "0x148d80",
    "target_elf_va": "0x148d80",
    "target_string": "CSRFTOKEN"
  },
  "0012be10": {
    "elf_va": "0x12be10",
    "file_offset": "0x11be10",
    "raw_u32": "0x148d70",
    "target_elf_va": "0x148d70",
    "target_string": "passwordStatus"
  },
  "0012be14": {
    "elf_va": "0x12be14",
    "file_offset": "0x11be14",
    "raw_u32": "0x148cfc",
    "target_elf_va": "0x148cfc",
    "target_string": "Status: 401 Unauthorized \n"
  },
  "0012be18": {
    "elf_va": "0x12be18",
    "file_offset": "0x11be18",
    "raw_u32": "0x148d18",
    "target_elf_va": "0x148d18",
    "target_string": "Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n"
  },
  "0012be1c": {
    "elf_va": "0x12be1c",
    "file_offset": "0x11be1c",
    "raw_u32": "0x147aa0",
    "target_elf_va": "0x147aa0",
    "target_string": "application/json"
  },
  "0012be20": {
    "elf_va": "0x12be20",
    "file_offset": "0x11be20",
    "raw_u32": "0x147a78",
    "target_elf_va": "0x147a78",
    "target_string": "cc"
  },
  "0012be24": {
    "elf_va": "0x12be24",
    "file_offset": "0x11be24",
    "raw_u32": "0x148d58",
    "target_elf_va": "0x148d58",
    "target_string": "Invalid Authentication"
  },
  "0012be28": {
    "elf_va": "0x12be28",
    "file_offset": "0x11be28",
    "raw_u32": "0x1533bc",
    "target_elf_va": "0x1533bc",
    "target_string": "error"
  },
  "0012be2c": {
    "elf_va": "0x12be2c",
    "file_offset": "0x11be2c",
    "raw_u32": "0x148c34",
    "target_elf_va": "0x148c34",
    "target_string": "%s"
  },
  "0012be30": {
    "elf_va": "0x12be30",
    "file_offset": "0x11be30",
    "raw_u32": "0x148d8c",
    "target_elf_va": "0x148d8c",
    "target_string": "Password should be changed for default user and should have a minimum of 8 characters."
  },
  "0012be34": {
    "elf_va": "0x12be34",
    "file_offset": "0x11be34",
    "raw_u32": "0x147268",
    "target_elf_va": "0x147268",
    "target_string": "REQUEST_METHOD"
  },
  "0012be38": {
    "elf_va": "0x12be38",
    "file_offset": "0x11be38",
    "raw_u32": "0x148de4",
    "target_elf_va": "0x148de4",
    "target_string": "CONTENT_TYPE"
  },
  "0012be3c": {
    "elf_va": "0x12be3c",
    "file_offset": "0x11be3c",
    "raw_u32": "0x148df4",
    "target_elf_va": "0x148df4",
    "target_string": "GET"
  },
  "0012be40": {
    "elf_va": "0x12be40",
    "file_offset": "0x11be40",
    "raw_u32": "0x156408",
    "target_elf_va": "0x156408",
    "target_string": "Error in Firmware Upgrade Status"
  },
  "0012be44": {
    "elf_va": "0x12be44",
    "file_offset": "0x11be44",
    "raw_u32": "0x55d",
    "target_elf_va": "0x55d"
  },
  "0012be48": {
    "elf_va": "0x12be48",
    "file_offset": "0x11be48",
    "raw_u32": "0x148e24",
    "target_elf_va": "0x148e24",
    "target_string": "code"
  },
  "0012be4c": {
    "elf_va": "0x12be4c",
    "file_offset": "0x11be4c",
    "raw_u32": "0x148e78",
    "target_elf_va": "0x148e78",
    "target_string": "500 Internal Server Error"
  },
  "0012be50": {
    "elf_va": "0x12be50",
    "file_offset": "0x11be50",
    "raw_u32": "0x148e40",
    "target_elf_va": "0x148e40",
    "target_string": "Status: %s \n"
  },
  "0012be54": {
    "elf_va": "0x12be54",
    "file_offset": "0x11be54",
    "raw_u32": "0x150f84",
    "target_elf_va": "0x150f84",
    "target_string": "unique_id"
  }
}
*/

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

