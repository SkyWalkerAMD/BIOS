
void getBIOSVersions_func(void)

{
  int iVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  size_t sVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  void *__ptr;
  int iVar10;
  int iStack_100ec;
  undefined4 uStack_100d4;
  undefined4 uStack_100d0;
  undefined4 uStack_100cc;
  undefined4 uStack_100c8;
  undefined4 uStack_100c4;
  undefined4 uStack_100c0;
  undefined4 uStack_100bc;
  undefined4 uStack_100b8;
  undefined4 uStack_100b4;
  undefined4 uStack_100b0;
  undefined1 auStack_100ac [7];
  undefined1 auStack_100a5 [113];
  undefined1 auStack_10034 [4];
  int iStack_10030;
  undefined1 auStack_1002a [65542];
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_000eef60);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_000eef70);
    FCGI_printf(DAT_000eef74);
    qcgires_setcontenttype(iVar1,DAT_000eef78);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_000eef7c,uVar8);
    uVar8 = json_object_new_string(DAT_000eef80);
    json_object_object_add(uVar9,DAT_000eef84,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_000eef88,uVar8);
    json_object_put(uVar9);
    goto LAB_000ee844;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000eef64);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000eef68,0);
    pcVar6 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000eef68,0);
    sVar7 = strlen(pcVar6);
    iVar4 = strncmp(pcVar5,pcVar2,sVar7);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000eef6c), iVar4 != 0))
    goto LAB_000ee794;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iStack_100ec = json_object_new_object();
    pcVar2 = getenv(DAT_000eef90);
    pcVar5 = getenv(DAT_000eef94);
    if ((pcVar2 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar2,DAT_000eef98),
       iVar10 != 0 && (pcVar5 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(iStack_100ec);
      iStack_100ec = json_tokener_parse(__ptr);
    }
    uStack_100d0 = 0;
    uStack_100cc = 0;
    uStack_100c8 = 0;
    uStack_100c4 = 0;
    uStack_100d4 = 0;
    uStack_100c0 = 0;
    uStack_100bc = 0;
    uStack_100b8 = 0;
    uStack_100b4 = 0;
    uStack_100b0 = 0;
    iVar10 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000eef9c);
    if (iVar10 < 4) {
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 == (char *)0x0) {
        iStack_100ec = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000eefa0,0x16);
        json_object_object_add(iStack_100ec,DAT_000eef84,uVar9);
        uVar9 = json_object_new_int(8000);
        json_object_object_add(iStack_100ec,DAT_000eefa4,uVar9);
        uVar9 = DAT_000eefa8;
LAB_000eed64:
        FCGI_printf(DAT_000eefb8,uVar9);
        qcgires_setcontenttype(iVar1,DAT_000eef78);
        uVar9 = json_object_to_json_string(iStack_100ec);
        FCGI_printf(DAT_000eef88,uVar9);
      }
      else {
        iVar4 = strcasecmp(pcVar2,DAT_000eef98);
        if ((iVar4 != 0 && pcVar5 != (char *)0x0) &&
           (iVar4 = strcasecmp(pcVar2,DAT_000eefc4), iVar4 == 0)) {
          strncasecmp(pcVar5,DAT_000eef78,0x10);
        }
        if (iStack_100ec != 0) {
          json_object_put(iStack_100ec);
        }
        iVar4 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000eefa0,0x16);
        json_object_object_add(iVar4,DAT_000eef84,uVar9);
        uVar9 = json_object_new_int(8000);
        json_object_object_add(iVar4,DAT_000eefa4,uVar9);
        uVar9 = DAT_000eefa8;
LAB_000eeb04:
        FCGI_printf(DAT_000eefb8,uVar9);
        qcgires_setcontenttype(iVar1,DAT_000eef78);
        uVar9 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_000eef88,uVar9);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_000eef98);
      }
joined_r0x000eeb50:
      if (iStack_100ec != 0) {
        json_object_put(iStack_100ec);
      }
    }
    else {
      memset(auStack_100ac,0,0x78);
      CMD_Get_BIOSFirmware_Version(auStack_10034,1);
      if (iStack_10030 != 0) {
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar2 != (char *)0x0) {
          iVar4 = strcasecmp(pcVar2,DAT_000eef98);
          if ((iVar4 != 0 && pcVar5 != (char *)0x0) &&
             (iVar4 = strcasecmp(pcVar2,DAT_000eefc4), iVar4 == 0)) {
            strncasecmp(pcVar5,DAT_000eef78,0x10);
          }
          if (iStack_100ec != 0) {
            json_object_put(iStack_100ec);
          }
          iVar4 = json_object_new_object();
          uVar9 = json_object_new_string_len(DAT_000eefac,0x26);
          json_object_object_add(iVar4,DAT_000eef84,uVar9);
          uVar9 = json_object_new_int(DAT_000eefb0);
          json_object_object_add(iVar4,DAT_000eefa4,uVar9);
          uVar9 = DAT_000eefb4;
          goto LAB_000eeb04;
        }
        iStack_100ec = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000eefac,0x26);
        json_object_object_add(iStack_100ec,DAT_000eef84,uVar9);
        uVar9 = DAT_000eefb0;
LAB_000eedc4:
        uVar9 = json_object_new_int(uVar9);
        json_object_object_add(iStack_100ec,DAT_000eefa4,uVar9);
        uVar9 = DAT_000eefb4;
        goto LAB_000eed64;
      }
      memcpy(auStack_100ac,auStack_1002a,0x78);
      snprintf((char *)&uStack_100d4,0x14,DAT_000eef88,auStack_100a5);
      memset(auStack_100ac,0,0x78);
      CMD_Get_BIOSFirmware_Version(auStack_10034,2);
      if (iStack_10030 == 0) {
        memcpy(auStack_100ac,auStack_1002a,0x78);
        snprintf((char *)&uStack_100c0,0x14,DAT_000eef88,auStack_100a5);
        sVar7 = strlen((char *)&uStack_100d4);
        uVar9 = json_object_new_string_len(&uStack_100d4,sVar7);
        json_object_object_add(iVar4,DAT_000eefc8,uVar9);
        sVar7 = strlen((char *)&uStack_100c0);
        uVar9 = json_object_new_string_len(&uStack_100c0,sVar7);
        json_object_object_add(iVar4,DAT_000eefcc,uVar9);
        qcgires_setcontenttype(iVar1,DAT_000eef78);
        uVar9 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_000eef88,uVar9);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar2 != (char *)0x0) {
          iVar4 = strcasecmp(pcVar2,DAT_000eef98);
          if (iVar4 != 0 && pcVar5 != (char *)0x0) goto LAB_000eecb4;
          goto joined_r0x000eeb50;
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
          iStack_100ec = json_object_new_object();
          uVar9 = json_object_new_string_len(DAT_000eefbc,0x26);
          json_object_object_add(iStack_100ec,DAT_000eef84,uVar9);
          uVar9 = DAT_000eefc0;
          goto LAB_000eedc4;
        }
        iVar4 = strcasecmp(pcVar2,DAT_000eef98);
        pcVar6 = pcVar5;
        if (pcVar5 != (char *)0x0) {
          pcVar6 = (char *)0x1;
        }
        if ((iVar4 != 0 && pcVar5 != (char *)0x0) &&
           (iVar4 = strcasecmp(pcVar2,DAT_000eefc4), iVar4 == 0)) {
          strncasecmp(pcVar5,DAT_000eef78,0x10);
        }
        if (iStack_100ec != 0) {
          json_object_put(iStack_100ec);
        }
        iVar4 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000eefbc,0x26);
        json_object_object_add(iVar4,DAT_000eef84,uVar9);
        uVar9 = json_object_new_int(DAT_000eefc0);
        json_object_object_add(iVar4,DAT_000eefa4,uVar9);
        FCGI_printf(DAT_000eefb8,DAT_000eefb4);
        qcgires_setcontenttype(iVar1,DAT_000eef78);
        uVar9 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_000eef88,uVar9);
        if ((iVar4 != 0) && (json_object_put(iVar4), pcVar6 = pcVar5, pcVar5 != (char *)0x0)) {
          pcVar6 = (char *)0x1;
        }
        iVar4 = strcasecmp(pcVar2,DAT_000eef98);
        if (iVar4 == 0) {
          pcVar6 = (char *)0x0;
        }
        if (pcVar6 != (char *)0x0) goto joined_r0x000eeb50;
LAB_000eecb4:
        if (iStack_100ec != 0) {
          json_object_put(iStack_100ec);
        }
      }
    }
  }
  else {
LAB_000ee794:
    FCGI_printf(DAT_000eef70);
    FCGI_printf(DAT_000eef74);
    qcgires_setcontenttype(iVar1,DAT_000eef78);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_000eef7c,uVar9);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000eef6c);
    uVar9 = DAT_000eef80;
    if (iVar4 == 1) {
      uVar9 = DAT_000eef8c;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_000eef84,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_000eef88,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_000ee844:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

