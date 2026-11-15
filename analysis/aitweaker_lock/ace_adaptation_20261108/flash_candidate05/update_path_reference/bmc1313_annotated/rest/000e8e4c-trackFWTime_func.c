/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "000e919c": {
    "elf_va": "0xe919c",
    "file_offset": "0xd919c",
    "raw_u32": "0x148ce8",
    "target_elf_va": "0x148ce8",
    "target_string": "HTTP_X_CSRFTOKEN"
  },
  "000e91a0": {
    "elf_va": "0xe91a0",
    "file_offset": "0xd91a0",
    "raw_u32": "0x150c40",
    "target_elf_va": "0x150c40",
    "target_string": "authorized"
  },
  "000e91a4": {
    "elf_va": "0xe91a4",
    "file_offset": "0xd91a4",
    "raw_u32": "0x148d80",
    "target_elf_va": "0x148d80",
    "target_string": "CSRFTOKEN"
  },
  "000e91a8": {
    "elf_va": "0xe91a8",
    "file_offset": "0xd91a8",
    "raw_u32": "0x148d70",
    "target_elf_va": "0x148d70",
    "target_string": "passwordStatus"
  },
  "000e91ac": {
    "elf_va": "0xe91ac",
    "file_offset": "0xd91ac",
    "raw_u32": "0x148cfc",
    "target_elf_va": "0x148cfc",
    "target_string": "Status: 401 Unauthorized \n"
  },
  "000e91b0": {
    "elf_va": "0xe91b0",
    "file_offset": "0xd91b0",
    "raw_u32": "0x148d18",
    "target_elf_va": "0x148d18",
    "target_string": "Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n"
  },
  "000e91b4": {
    "elf_va": "0xe91b4",
    "file_offset": "0xd91b4",
    "raw_u32": "0x147aa0",
    "target_elf_va": "0x147aa0",
    "target_string": "application/json"
  },
  "000e91b8": {
    "elf_va": "0xe91b8",
    "file_offset": "0xd91b8",
    "raw_u32": "0x147a78",
    "target_elf_va": "0x147a78",
    "target_string": "cc"
  },
  "000e91bc": {
    "elf_va": "0xe91bc",
    "file_offset": "0xd91bc",
    "raw_u32": "0x148d58",
    "target_elf_va": "0x148d58",
    "target_string": "Invalid Authentication"
  },
  "000e91c0": {
    "elf_va": "0xe91c0",
    "file_offset": "0xd91c0",
    "raw_u32": "0x148d8c",
    "target_elf_va": "0x148d8c",
    "target_string": "Password should be changed for default user and should have a minimum of 8 characters."
  },
  "000e91c4": {
    "elf_va": "0xe91c4",
    "file_offset": "0xd91c4",
    "raw_u32": "0x1533bc",
    "target_elf_va": "0x1533bc",
    "target_string": "error"
  },
  "000e91c8": {
    "elf_va": "0xe91c8",
    "file_offset": "0xd91c8",
    "raw_u32": "0x148c34",
    "target_elf_va": "0x148c34",
    "target_string": "%s"
  },
  "000e91cc": {
    "elf_va": "0xe91cc",
    "file_offset": "0xd91cc",
    "raw_u32": "0x147268",
    "target_elf_va": "0x147268",
    "target_string": "REQUEST_METHOD"
  },
  "000e91d0": {
    "elf_va": "0xe91d0",
    "file_offset": "0xd91d0",
    "raw_u32": "0x148de4",
    "target_elf_va": "0x148de4",
    "target_string": "CONTENT_TYPE"
  },
  "000e91d4": {
    "elf_va": "0xe91d4",
    "file_offset": "0xd91d4",
    "raw_u32": "0x148df4",
    "target_elf_va": "0x148df4",
    "target_string": "GET"
  },
  "000e91d8": {
    "elf_va": "0xe91d8",
    "file_offset": "0xd91d8",
    "raw_u32": "0x15239c",
    "target_elf_va": "0x15239c",
    "target_string": "ok"
  },
  "000e91dc": {
    "elf_va": "0xe91dc",
    "file_offset": "0xd91dc",
    "raw_u32": "0x15615c",
    "target_elf_va": "0x15615c",
    "target_string": "status"
  }
}
*/

void trackFWTime_func(void)

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
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_000e919c);
  pre_call_hook(iVar1);
  qcgisess_validate(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_000e91ac);
    FCGI_printf(DAT_000e91b0);
    qcgires_setcontenttype(iVar1,DAT_000e91b4);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_000e91b8,uVar6);
    uVar6 = json_object_new_string(DAT_000e91bc);
    json_object_object_add(uVar7,DAT_000e91c4,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_000e91c8,uVar6);
    json_object_put(uVar7);
    goto LAB_000e8fc8;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e91a0);
  if (pcVar2 == (char *)0x0 || iVar4 != 1) {
LAB_000e8f18:
    FCGI_printf(DAT_000e91ac);
    FCGI_printf(DAT_000e91b0);
    qcgires_setcontenttype(iVar1,DAT_000e91b4);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_000e91b8,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e91a8);
    uVar7 = DAT_000e91bc;
    if (iVar4 == 1) {
      uVar7 = DAT_000e91c0;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_000e91c4,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_000e91c8,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  else {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000e91a4,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000e91a4,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e91a8), iVar4 != 0))
    goto LAB_000e8f18;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_000e91cc);
    pcVar5 = getenv(DAT_000e91d0);
    if ((pcVar2 == (char *)0x0) ||
       (iVar9 = strcasecmp(pcVar2,DAT_000e91d4), __ptr == (void *)0x0 || iVar9 == 0)) {
      uVar7 = json_object_new_string_len(DAT_000e91d8,2);
      json_object_object_add(iVar4,DAT_000e91dc,uVar7);
      qcgires_setcontenttype(iVar1,DAT_000e91b4);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000e91c8,uVar7);
      if (iVar4 != 0) goto LAB_000e9084;
LAB_000e908c:
      if (__ptr != (void *)0x0) goto LAB_000e9190;
    }
    else {
      if (pcVar5 != (char *)0x0) {
        json_object_put(iVar8);
        iVar8 = json_tokener_parse(__ptr);
      }
      uVar7 = json_object_new_string_len(DAT_000e91d8,2);
      json_object_object_add(iVar4,DAT_000e91dc,uVar7);
      qcgires_setcontenttype(iVar1,DAT_000e91b4);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000e91c8,uVar7);
      if (iVar4 != 0) {
LAB_000e9084:
        json_object_put(iVar4);
        goto LAB_000e908c;
      }
LAB_000e9190:
      free(__ptr);
    }
    if ((pcVar2 != (char *)0x0) && (strcasecmp(pcVar2,DAT_000e91d4), iVar8 != 0)) {
      json_object_put(iVar8);
    }
  }
  post_authorized_call_hook(iVar1,iVar3);
  pollqcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_000e8fc8:
  post_call_hook(iVar1);
                    /* WARNING: Could not recover jumptable at 0x000e8fdc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

