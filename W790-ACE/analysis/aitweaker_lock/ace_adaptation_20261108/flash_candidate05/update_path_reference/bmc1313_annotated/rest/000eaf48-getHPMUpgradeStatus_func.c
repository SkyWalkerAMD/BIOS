/* ELF literal/relocation annotations (Ghidra bias 0x0).
{
  "000eb464": {
    "elf_va": "0xeb464",
    "file_offset": "0xdb464",
    "raw_u32": "0x148ce8",
    "target_elf_va": "0x148ce8",
    "target_string": "HTTP_X_CSRFTOKEN"
  },
  "000eb468": {
    "elf_va": "0xeb468",
    "file_offset": "0xdb468",
    "raw_u32": "0x150c40",
    "target_elf_va": "0x150c40",
    "target_string": "authorized"
  },
  "000eb46c": {
    "elf_va": "0xeb46c",
    "file_offset": "0xdb46c",
    "raw_u32": "0x148d80",
    "target_elf_va": "0x148d80",
    "target_string": "CSRFTOKEN"
  },
  "000eb470": {
    "elf_va": "0xeb470",
    "file_offset": "0xdb470",
    "raw_u32": "0x148d70",
    "target_elf_va": "0x148d70",
    "target_string": "passwordStatus"
  },
  "000eb474": {
    "elf_va": "0xeb474",
    "file_offset": "0xdb474",
    "raw_u32": "0x148cfc",
    "target_elf_va": "0x148cfc",
    "target_string": "Status: 401 Unauthorized \n"
  },
  "000eb478": {
    "elf_va": "0xeb478",
    "file_offset": "0xdb478",
    "raw_u32": "0x148d18",
    "target_elf_va": "0x148d18",
    "target_string": "Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n"
  },
  "000eb47c": {
    "elf_va": "0xeb47c",
    "file_offset": "0xdb47c",
    "raw_u32": "0x147aa0",
    "target_elf_va": "0x147aa0",
    "target_string": "application/json"
  },
  "000eb480": {
    "elf_va": "0xeb480",
    "file_offset": "0xdb480",
    "raw_u32": "0x147a78",
    "target_elf_va": "0x147a78",
    "target_string": "cc"
  },
  "000eb484": {
    "elf_va": "0xeb484",
    "file_offset": "0xdb484",
    "raw_u32": "0x148d58",
    "target_elf_va": "0x148d58",
    "target_string": "Invalid Authentication"
  },
  "000eb488": {
    "elf_va": "0xeb488",
    "file_offset": "0xdb488",
    "raw_u32": "0x1533bc",
    "target_elf_va": "0x1533bc",
    "target_string": "error"
  },
  "000eb48c": {
    "elf_va": "0xeb48c",
    "file_offset": "0xdb48c",
    "raw_u32": "0x148c34",
    "target_elf_va": "0x148c34",
    "target_string": "%s"
  },
  "000eb490": {
    "elf_va": "0xeb490",
    "file_offset": "0xdb490",
    "raw_u32": "0x148d8c",
    "target_elf_va": "0x148d8c",
    "target_string": "Password should be changed for default user and should have a minimum of 8 characters."
  },
  "000eb494": {
    "elf_va": "0xeb494",
    "file_offset": "0xdb494",
    "raw_u32": "0x147268",
    "target_elf_va": "0x147268",
    "target_string": "REQUEST_METHOD"
  },
  "000eb498": {
    "elf_va": "0xeb498",
    "file_offset": "0xdb498",
    "raw_u32": "0x148de4",
    "target_elf_va": "0x148de4",
    "target_string": "CONTENT_TYPE"
  },
  "000eb49c": {
    "elf_va": "0xeb49c",
    "file_offset": "0xdb49c",
    "raw_u32": "0x148df4",
    "target_elf_va": "0x148df4",
    "target_string": "GET"
  },
  "000eb4a0": {
    "elf_va": "0xeb4a0",
    "file_offset": "0xdb4a0",
    "raw_u32": "0x150fc4",
    "target_elf_va": "0x150fc4",
    "target_string": "COMPONENT_ID"
  },
  "000eb4a4": {
    "elf_va": "0xeb4a4",
    "file_offset": "0xdb4a4",
    "raw_u32": "0x1510c8",
    "target_elf_va": "0x1510c8",
    "target_string": "PROGRESS"
  },
  "000eb4a8": {
    "elf_va": "0xeb4a8",
    "file_offset": "0xdb4a8",
    "raw_u32": "0x151024",
    "target_elf_va": "0x151024",
    "target_string": "Error in HPM Finish Firmware Upload"
  },
  "000eb4ac": {
    "elf_va": "0xeb4ac",
    "file_offset": "0xdb4ac",
    "raw_u32": "0x55d",
    "target_elf_va": "0x55d"
  },
  "000eb4b0": {
    "elf_va": "0xeb4b0",
    "file_offset": "0xdb4b0",
    "raw_u32": "0x148e24",
    "target_elf_va": "0x148e24",
    "target_string": "code"
  },
  "000eb4b4": {
    "elf_va": "0xeb4b4",
    "file_offset": "0xdb4b4",
    "raw_u32": "0x148e78",
    "target_elf_va": "0x148e78",
    "target_string": "500 Internal Server Error"
  },
  "000eb4b8": {
    "elf_va": "0xeb4b8",
    "file_offset": "0xdb4b8",
    "raw_u32": "0x148e40",
    "target_elf_va": "0x148e40",
    "target_string": "Status: %s \n"
  }
}
*/

void getHPMUpgradeStatus_func(void)

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
  pcVar2 = getenv(DAT_000eb464);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_000eb474);
    FCGI_printf(DAT_000eb478);
    qcgires_setcontenttype(iVar1,DAT_000eb47c);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_000eb480,uVar6);
    uVar6 = json_object_new_string(DAT_000eb484);
    json_object_object_add(uVar7,DAT_000eb488,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_000eb48c,uVar6);
    json_object_put(uVar7);
    goto LAB_000eb0c4;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000eb468);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000eb46c,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000eb46c,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000eb470), iVar4 != 0))
    goto LAB_000eb014;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_000eb494);
    pcVar5 = getenv(DAT_000eb498);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_000eb49c),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    pcVar5 = (char *)(**(code **)(iVar1 + 0x18))(iVar1,DAT_000eb4a0,0);
    snprintf(acStack_10040,10,DAT_000eb48c,pcVar5);
    uVar10 = strtol(pcVar5,(char **)0x0,10);
    uVar10 = uVar10 & 0xff;
    CMD_Get_Firmware_Progress(auStack_10034,uVar10,1,&uStack_10044,1);
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,DAT_000eb4a0,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,DAT_000eb4a4,uVar7);
      qcgires_setcontenttype(iVar1,DAT_000eb47c);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000eb48c,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_000eb49c);
LAB_000eb348:
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
      }
    }
    else {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,DAT_000eb4a0,uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,DAT_000eb4a4,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_000eb49c);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_000eb4a8,0x23);
        json_object_object_add(iVar4,DAT_000eb488,uVar7);
        uVar7 = json_object_new_int(DAT_000eb4ac);
        json_object_object_add(iVar4,DAT_000eb4b0,uVar7);
        FCGI_printf(DAT_000eb4b8,DAT_000eb4b4);
        qcgires_setcontenttype(iVar1,DAT_000eb47c);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_000eb48c,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_000eb49c);
        goto LAB_000eb348;
      }
      iVar4 = json_object_new_object();
      uVar7 = json_object_new_string_len(DAT_000eb4a8,0x23);
      json_object_object_add(iVar4,DAT_000eb488,uVar7);
      uVar7 = json_object_new_int(DAT_000eb4ac);
      json_object_object_add(iVar4,DAT_000eb4b0,uVar7);
      FCGI_printf(DAT_000eb4b8,DAT_000eb4b4);
      qcgires_setcontenttype(iVar1,DAT_000eb47c);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000eb48c,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
    }
  }
  else {
LAB_000eb014:
    FCGI_printf(DAT_000eb474);
    FCGI_printf(DAT_000eb478);
    qcgires_setcontenttype(iVar1,DAT_000eb47c);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_000eb480,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000eb470);
    uVar7 = DAT_000eb484;
    if (iVar4 == 1) {
      uVar7 = DAT_000eb490;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_000eb488,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_000eb48c,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_000eb0c4:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

