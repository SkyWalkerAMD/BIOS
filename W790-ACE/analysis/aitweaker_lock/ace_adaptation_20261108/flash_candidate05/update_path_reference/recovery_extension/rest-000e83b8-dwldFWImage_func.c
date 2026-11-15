/* Exact ELF literal map, no Ghidra bias for this ET_EXEC. */
{
  "000e8894": {
    "elf_va": "0xe8894",
    "file_offset": "0xd8894",
    "raw_u32": "0x148ce8",
    "target_elf_va": "0x148ce8",
    "target_string": "HTTP_X_CSRFTOKEN"
  },
  "000e8898": {
    "elf_va": "0xe8898",
    "file_offset": "0xd8898",
    "raw_u32": "0x150c40",
    "target_elf_va": "0x150c40",
    "target_string": "authorized"
  },
  "000e889c": {
    "elf_va": "0xe889c",
    "file_offset": "0xd889c",
    "raw_u32": "0x148d80",
    "target_elf_va": "0x148d80",
    "target_string": "CSRFTOKEN"
  },
  "000e88a0": {
    "elf_va": "0xe88a0",
    "file_offset": "0xd88a0",
    "raw_u32": "0x148d70",
    "target_elf_va": "0x148d70",
    "target_string": "passwordStatus"
  },
  "000e88a4": {
    "elf_va": "0xe88a4",
    "file_offset": "0xd88a4",
    "raw_u32": "0x148cfc",
    "target_elf_va": "0x148cfc",
    "target_string": "Status: 401 Unauthorized \n"
  },
  "000e88a8": {
    "elf_va": "0xe88a8",
    "file_offset": "0xd88a8",
    "raw_u32": "0x148d18",
    "target_elf_va": "0x148d18",
    "target_string": "Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n"
  },
  "000e88ac": {
    "elf_va": "0xe88ac",
    "file_offset": "0xd88ac",
    "raw_u32": "0x147aa0",
    "target_elf_va": "0x147aa0",
    "target_string": "application/json"
  },
  "000e88b0": {
    "elf_va": "0xe88b0",
    "file_offset": "0xd88b0",
    "raw_u32": "0x147a78",
    "target_elf_va": "0x147a78",
    "target_string": "cc"
  },
  "000e88b4": {
    "elf_va": "0xe88b4",
    "file_offset": "0xd88b4",
    "raw_u32": "0x148d58",
    "target_elf_va": "0x148d58",
    "target_string": "Invalid Authentication"
  },
  "000e88b8": {
    "elf_va": "0xe88b8",
    "file_offset": "0xd88b8",
    "raw_u32": "0x1533bc",
    "target_elf_va": "0x1533bc",
    "target_string": "error"
  },
  "000e88bc": {
    "elf_va": "0xe88bc",
    "file_offset": "0xd88bc",
    "raw_u32": "0x148c34",
    "target_elf_va": "0x148c34",
    "target_string": "%s"
  },
  "000e88c0": {
    "elf_va": "0xe88c0",
    "file_offset": "0xd88c0",
    "raw_u32": "0x148d8c",
    "target_elf_va": "0x148d8c",
    "target_string": "Password should be changed for default user and should have a minimum of 8 characters."
  },
  "000e88c4": {
    "elf_va": "0xe88c4",
    "file_offset": "0xd88c4",
    "raw_u32": "0x147268",
    "target_elf_va": "0x147268",
    "target_string": "REQUEST_METHOD"
  },
  "000e88c8": {
    "elf_va": "0xe88c8",
    "file_offset": "0xd88c8",
    "raw_u32": "0x148de4",
    "target_elf_va": "0x148de4",
    "target_string": "CONTENT_TYPE"
  },
  "000e88cc": {
    "elf_va": "0xe88cc",
    "file_offset": "0xd88cc",
    "raw_u32": "0x148df4",
    "target_elf_va": "0x148df4",
    "target_string": "GET"
  },
  "000e88d0": {
    "elf_va": "0xe88d0",
    "file_offset": "0xd88d0",
    "raw_u32": "0x150e64",
    "target_elf_va": "0x150e64",
    "target_string": "PROTO_TYPE"
  },
  "000e88d4": {
    "elf_va": "0xe88d4",
    "file_offset": "0xd88d4",
    "raw_u32": "0x150e70",
    "target_elf_va": "0x150e70",
    "target_string": "Error in downloading firmware image"
  },
  "000e88d8": {
    "elf_va": "0xe88d8",
    "file_offset": "0xd88d8",
    "raw_u32": "0x148e24",
    "target_elf_va": "0x148e24",
    "target_string": "code"
  },
  "000e88dc": {
    "elf_va": "0xe88dc",
    "file_offset": "0xd88dc",
    "raw_u32": "0x148e78",
    "target_elf_va": "0x148e78",
    "target_string": "500 Internal Server Error"
  },
  "000e88e0": {
    "elf_va": "0xe88e0",
    "file_offset": "0xd88e0",
    "raw_u32": "0x148e40",
    "target_elf_va": "0x148e40",
    "target_string": "Status: %s \n"
  }
}

void dwldFWImage_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  size_t __n;
  undefined4 uVar8;
  undefined4 uVar9;
  void *__ptr;
  int iVar10;
  int iVar11;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_000e8894);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_000e88a4);
    FCGI_printf(DAT_000e88a8);
    qcgires_setcontenttype(iVar2,DAT_000e88ac);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_000e88b0,uVar8);
    uVar8 = json_object_new_string(DAT_000e88b4);
    json_object_object_add(uVar9,DAT_000e88b8,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_000e88bc,uVar8);
    json_object_put(uVar9);
    goto LAB_000e8530;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e8898);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000e889c,0);
    pcVar7 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000e889c,0);
    __n = strlen(pcVar7);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e88a0), iVar5 != 0))
    goto LAB_000e8480;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar10 = json_object_new_object();
    pcVar3 = getenv(DAT_000e88c4);
    pcVar6 = getenv(DAT_000e88c8);
    if ((pcVar3 != (char *)0x0) &&
       (iVar11 = strcasecmp(pcVar3,DAT_000e88cc),
       iVar11 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar10);
      iVar10 = json_tokener_parse(__ptr);
    }
    iVar11 = json_object_object_get_rest(iVar10,DAT_000e88d0);
    if (iVar11 == 0) {
      uVar1 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar10,DAT_000e88d0);
      uVar1 = json_object_get_int();
    }
    iVar11 = DownloadFwImage(uVar1);
    if (iVar11 == 0) {
      pcVar6 = getenv(DAT_000e88c4);
      pcVar7 = getenv(DAT_000e88c8);
      if (((pcVar6 != (char *)0x0 && pcVar7 != (char *)0x0) &&
          (iVar11 = strcasecmp(pcVar6,DAT_000e88cc), iVar11 != 0)) &&
         (iVar11 = strncasecmp(pcVar7,DAT_000e88ac,0x10), iVar11 == 0)) {
        qcgires_setcontenttype(iVar2,DAT_000e88ac);
        uVar9 = json_object_to_json_string(iVar10);
        FCGI_printf(DAT_000e88bc,uVar9);
      }
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_000e88cc);
        goto LAB_000e86cc;
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
        uVar9 = json_object_new_string_len(DAT_000e88d4,0x23);
        json_object_object_add(iVar5,DAT_000e88b8,uVar9);
        uVar9 = json_object_new_int(iVar11);
        json_object_object_add(iVar5,DAT_000e88d8,uVar9);
        FCGI_printf(DAT_000e88e0,DAT_000e88dc);
        qcgires_setcontenttype(iVar2,DAT_000e88ac);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_000e88bc,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
      }
      else {
        strcasecmp(pcVar3,DAT_000e88cc);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000e88d4,0x23);
        json_object_object_add(iVar5,DAT_000e88b8,uVar9);
        uVar9 = json_object_new_int(iVar11);
        json_object_object_add(iVar5,DAT_000e88d8,uVar9);
        FCGI_printf(DAT_000e88e0,DAT_000e88dc);
        qcgires_setcontenttype(iVar2,DAT_000e88ac);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_000e88bc,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_000e88cc);
LAB_000e86cc:
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
      }
    }
  }
  else {
LAB_000e8480:
    FCGI_printf(DAT_000e88a4);
    FCGI_printf(DAT_000e88a8);
    qcgires_setcontenttype(iVar2,DAT_000e88ac);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_000e88b0,uVar9);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e88a0);
    uVar9 = DAT_000e88b4;
    if (iVar5 == 1) {
      uVar9 = DAT_000e88c0;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_000e88b8,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_000e88bc,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_000e8530:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x000e8548. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

