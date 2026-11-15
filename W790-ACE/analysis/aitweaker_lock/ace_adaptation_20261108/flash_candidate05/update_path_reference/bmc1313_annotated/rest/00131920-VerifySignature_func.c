/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "00131d8c": {
    "elf_va": "0x131d8c",
    "file_offset": "0x121d8c",
    "raw_u32": "0x148ce8",
    "target_elf_va": "0x148ce8",
    "target_string": "HTTP_X_CSRFTOKEN"
  },
  "00131d90": {
    "elf_va": "0x131d90",
    "file_offset": "0x121d90",
    "raw_u32": "0x150c40",
    "target_elf_va": "0x150c40",
    "target_string": "authorized"
  },
  "00131d94": {
    "elf_va": "0x131d94",
    "file_offset": "0x121d94",
    "raw_u32": "0x148d80",
    "target_elf_va": "0x148d80",
    "target_string": "CSRFTOKEN"
  },
  "00131d98": {
    "elf_va": "0x131d98",
    "file_offset": "0x121d98",
    "raw_u32": "0x148d70",
    "target_elf_va": "0x148d70",
    "target_string": "passwordStatus"
  },
  "00131d9c": {
    "elf_va": "0x131d9c",
    "file_offset": "0x121d9c",
    "raw_u32": "0x148cfc",
    "target_elf_va": "0x148cfc",
    "target_string": "Status: 401 Unauthorized \n"
  },
  "00131da0": {
    "elf_va": "0x131da0",
    "file_offset": "0x121da0",
    "raw_u32": "0x148d18",
    "target_elf_va": "0x148d18",
    "target_string": "Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n"
  },
  "00131da4": {
    "elf_va": "0x131da4",
    "file_offset": "0x121da4",
    "raw_u32": "0x147aa0",
    "target_elf_va": "0x147aa0",
    "target_string": "application/json"
  },
  "00131da8": {
    "elf_va": "0x131da8",
    "file_offset": "0x121da8",
    "raw_u32": "0x147a78",
    "target_elf_va": "0x147a78",
    "target_string": "cc"
  },
  "00131dac": {
    "elf_va": "0x131dac",
    "file_offset": "0x121dac",
    "raw_u32": "0x148d58",
    "target_elf_va": "0x148d58",
    "target_string": "Invalid Authentication"
  },
  "00131db0": {
    "elf_va": "0x131db0",
    "file_offset": "0x121db0",
    "raw_u32": "0x1533bc",
    "target_elf_va": "0x1533bc",
    "target_string": "error"
  },
  "00131db4": {
    "elf_va": "0x131db4",
    "file_offset": "0x121db4",
    "raw_u32": "0x148c34",
    "target_elf_va": "0x148c34",
    "target_string": "%s"
  },
  "00131db8": {
    "elf_va": "0x131db8",
    "file_offset": "0x121db8",
    "raw_u32": "0x148d8c",
    "target_elf_va": "0x148d8c",
    "target_string": "Password should be changed for default user and should have a minimum of 8 characters."
  },
  "00131dbc": {
    "elf_va": "0x131dbc",
    "file_offset": "0x121dbc",
    "raw_u32": "0x147268",
    "target_elf_va": "0x147268",
    "target_string": "REQUEST_METHOD"
  },
  "00131dc0": {
    "elf_va": "0x131dc0",
    "file_offset": "0x121dc0",
    "raw_u32": "0x148de4",
    "target_elf_va": "0x148de4",
    "target_string": "CONTENT_TYPE"
  },
  "00131dc4": {
    "elf_va": "0x131dc4",
    "file_offset": "0x121dc4",
    "raw_u32": "0x148df4",
    "target_elf_va": "0x148df4",
    "target_string": "GET"
  },
  "00131dc8": {
    "elf_va": "0x131dc8",
    "file_offset": "0x121dc8",
    "raw_u32": "0x156408",
    "target_elf_va": "0x156408",
    "target_string": "Error in Firmware Upgrade Status"
  },
  "00131dcc": {
    "elf_va": "0x131dcc",
    "file_offset": "0x121dcc",
    "raw_u32": "0x519",
    "target_elf_va": "0x519"
  },
  "00131dd0": {
    "elf_va": "0x131dd0",
    "file_offset": "0x121dd0",
    "raw_u32": "0x148e24",
    "target_elf_va": "0x148e24",
    "target_string": "code"
  },
  "00131dd4": {
    "elf_va": "0x131dd4",
    "file_offset": "0x121dd4",
    "raw_u32": "0x148e78",
    "target_elf_va": "0x148e78",
    "target_string": "500 Internal Server Error"
  },
  "00131dd8": {
    "elf_va": "0x131dd8",
    "file_offset": "0x121dd8",
    "raw_u32": "0x148e40",
    "target_elf_va": "0x148e40",
    "target_string": "Status: %s \n"
  }
}
*/

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
  pcVar2 = getenv(DAT_00131d8c);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_00131d9c);
    FCGI_printf(DAT_00131da0);
    qcgires_setcontenttype(iVar1,DAT_00131da4);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_00131da8,uVar6);
    uVar6 = json_object_new_string(DAT_00131dac);
    json_object_object_add(uVar7,DAT_00131db0,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_00131db4,uVar6);
    json_object_put(uVar7);
    goto LAB_00131a9c;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_00131d90);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_00131d94,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_00131d94,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_00131d98), iVar4 != 0))
    goto LAB_001319ec;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_00131dbc);
    pcVar5 = getenv(DAT_00131dc0);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_00131dc4),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    CMD_Verify_BIOS_Signature(auStack_1002c);
    if (iStack_10028 == 0) {
      qcgires_setcontenttype(iVar1,DAT_00131da4);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_00131db4,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_00131dc4);
        goto LAB_00131c18;
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
        uVar7 = json_object_new_string_len(DAT_00131dc8,0x20);
        json_object_object_add(iVar4,DAT_00131db0,uVar7);
        uVar7 = json_object_new_int(DAT_00131dcc);
        json_object_object_add(iVar4,DAT_00131dd0,uVar7);
        FCGI_printf(DAT_00131dd8,DAT_00131dd4);
        qcgires_setcontenttype(iVar1,DAT_00131da4);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_00131db4,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        strcasecmp(pcVar2,DAT_00131dc4);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_00131dc8,0x20);
        json_object_object_add(iVar4,DAT_00131db0,uVar7);
        uVar7 = json_object_new_int(DAT_00131dcc);
        json_object_object_add(iVar4,DAT_00131dd0,uVar7);
        FCGI_printf(DAT_00131dd8,DAT_00131dd4);
        qcgires_setcontenttype(iVar1,DAT_00131da4);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_00131db4,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_00131dc4);
LAB_00131c18:
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
      }
    }
  }
  else {
LAB_001319ec:
    FCGI_printf(DAT_00131d9c);
    FCGI_printf(DAT_00131da0);
    qcgires_setcontenttype(iVar1,DAT_00131da4);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_00131da8,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_00131d98);
    uVar7 = DAT_00131dac;
    if (iVar4 == 1) {
      uVar7 = DAT_00131db8;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_00131db0,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_00131db4,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_00131a9c:
  post_call_hook(iVar1);
                    /* WARNING: Could not recover jumptable at 0x00131ab8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

