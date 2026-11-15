
void getBIOSComponentCurrentVerisons_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  size_t sVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  void *__ptr;
  uint uVar11;
  int iVar12;
  char cVar13;
  undefined1 *local_98;
  int local_90;
  char *local_80;
  uint local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined2 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined1 auStack_54 [48];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_0012f74c);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0012f75c);
    FCGI_printf(DAT_0012f760);
    qcgires_setcontenttype(iVar2,DAT_0012f764);
    uVar10 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar10,DAT_0012f768,uVar9);
    uVar9 = json_object_new_string(DAT_0012f76c);
    json_object_object_add(uVar10,DAT_0012f770,uVar9);
    uVar9 = json_object_to_json_string(uVar10);
    FCGI_printf(DAT_0012f774,uVar9);
    json_object_put(uVar10);
    goto LAB_0012efe0;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012f750);
  if (pcVar3 == (char *)0x0 || iVar5 != 1) {
LAB_0012ef30:
    FCGI_printf(DAT_0012f75c);
    FCGI_printf(DAT_0012f760);
    qcgires_setcontenttype(iVar2,DAT_0012f764);
    uVar9 = json_object_new_object();
    uVar10 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_0012f768,uVar10);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012f758);
    uVar10 = DAT_0012f76c;
    if (iVar5 == 1) {
      uVar10 = DAT_0012f778;
    }
    uVar10 = json_object_new_string(uVar10);
    json_object_object_add(uVar9,DAT_0012f770,uVar10);
    uVar10 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_0012f774,uVar10);
    json_object_put(uVar9);
    qcgisess_clear(iVar4);
  }
  else {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012f754,0);
    pcVar7 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0012f754,0);
    sVar8 = strlen(pcVar7);
    iVar5 = strncmp(pcVar6,pcVar3,sVar8);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012f758), iVar5 != 0))
    goto LAB_0012ef30;
    pre_authorized_call_hook(iVar2,iVar4);
    uVar10 = json_object_new_array();
    __ptr = (void *)qcgireq_getquery(4);
    local_90 = json_object_new_object();
    pcVar3 = getenv(DAT_0012f77c);
    pcVar6 = getenv(DAT_0012f780);
    if ((pcVar3 != (char *)0x0) &&
       (iVar5 = strcasecmp(pcVar3,DAT_0012f784),
       iVar5 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(local_90);
      local_90 = json_tokener_parse(__ptr);
    }
    if (*DAT_0012f788 == 0) {
LAB_0012f0f0:
      local_98 = auStack_54;
      cVar13 = '\0';
      local_60 = 0;
      local_5c = 0;
      local_58 = 0;
      local_68 = 0;
      local_74 = 0;
      local_64 = 0;
      local_70 = 0;
      local_6c = 0;
      local_80 = (char *)&local_74;
      uVar9 = (**(code **)(iVar2 + 0x18))(iVar2,DAT_0012f794,0);
      snprintf((char *)&local_74,10,DAT_0012f774,uVar9);
      pcVar7 = strsep(&local_80,DAT_0012f798);
      if (pcVar7 != (char *)0x0) {
        do {
          local_7c = 0;
          local_78 = 0;
          uVar11 = strtol(pcVar7,(char **)0x0,10);
          iVar5 = LIBIPMI_HL_GetCompProperties_CurrVersion(local_98,uVar11 & 0xff,&local_7c,0x3c);
          snprintf((char *)&local_68,0x14,DAT_0012f79c,local_7c >> 0x10 & 0xff,local_7c >> 0x18,
                   local_78);
          iVar12 = json_object_new_object();
          uVar9 = json_object_new_int(cVar13);
          json_object_object_add(iVar12,DAT_0012f7a0,uVar9);
          sVar8 = strlen(pcVar7);
          uVar9 = json_object_new_string_len(pcVar7,sVar8);
          json_object_object_add(iVar12,DAT_0012f7a4,uVar9);
          sVar8 = strlen((char *)&local_68);
          uVar9 = json_object_new_string_len(&local_68,sVar8);
          json_object_object_add(iVar12,DAT_0012f7a8,uVar9);
          json_object_array_add(uVar10,iVar12);
          pcVar7 = strsep(&local_80,DAT_0012f798);
          cVar13 = cVar13 + '\x01';
        } while (pcVar7 != (char *)0x0);
        if (iVar5 != 0) {
          IPMI_lo_Logout(local_98);
          if (iVar12 != 0) {
            json_object_put(iVar12);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 != (char *)0x0) {
            iVar5 = strcasecmp(pcVar3,DAT_0012f784);
            pcVar7 = pcVar6;
            if (pcVar6 != (char *)0x0) {
              pcVar7 = (char *)0x1;
            }
            if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
               (iVar5 = strcasecmp(pcVar3,DAT_0012f7c0), iVar5 == 0)) {
              strncasecmp(pcVar6,DAT_0012f764,0x10);
            }
            if (local_90 != 0) {
              json_object_put(local_90);
            }
            iVar5 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_0012f7ac,0x1f);
            json_object_object_add(iVar5,DAT_0012f770,uVar10);
            uVar10 = json_object_new_int(DAT_0012f7b0);
            json_object_object_add(iVar5,DAT_0012f7b4,uVar10);
            FCGI_printf(DAT_0012f7bc,DAT_0012f7b8);
            qcgires_setcontenttype(iVar2,DAT_0012f764);
            uVar10 = json_object_to_json_string(iVar5);
            FCGI_printf(DAT_0012f774,uVar10);
            if ((iVar5 != 0) && (json_object_put(iVar5), pcVar7 = pcVar6, pcVar6 != (char *)0x0)) {
              pcVar7 = (char *)0x1;
            }
            iVar5 = strcasecmp(pcVar3,DAT_0012f784);
            if (iVar5 == 0) {
              pcVar7 = (char *)0x0;
            }
            if ((pcVar7 != (char *)0x0) && (iVar5 = strcasecmp(pcVar3,DAT_0012f7c0), iVar5 == 0)) {
              pcVar7 = (char *)strncasecmp(pcVar6,DAT_0012f764,0x10);
              goto joined_r0x0012f394;
            }
            goto LAB_0012f4a8;
          }
          local_90 = json_object_new_object();
          uVar10 = json_object_new_string_len(DAT_0012f7ac,0x1f);
          json_object_object_add(local_90,DAT_0012f770,uVar10);
          uVar10 = json_object_new_int(DAT_0012f7b0);
          json_object_object_add(local_90,DAT_0012f7b4,uVar10);
          uVar10 = DAT_0012f7b8;
          goto LAB_0012f558;
        }
      }
      qcgires_setcontenttype(iVar2,DAT_0012f764);
      uVar9 = json_object_to_json_string(uVar10);
      FCGI_printf(DAT_0012f774,uVar9);
      IPMI_lo_Logout(local_98);
      iVar12 = json_object_array_length(uVar10);
      iVar5 = 0;
      if (0 < iVar12) {
        do {
          json_object_array_get_idx(uVar10,iVar5);
          iVar5 = iVar5 + 1;
          json_object_put();
        } while (iVar12 != iVar5);
      }
      json_object_put(uVar10);
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0012f784);
LAB_0012f4a8:
        if (local_90 != 0) {
          json_object_put(local_90);
        }
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0012f78c);
      iVar5 = IPMI_lo_Login(DAT_0012f790,DAT_0012f790,auStack_54,uVar1,1,0,0,0);
      if (iVar5 == 0) goto LAB_0012f0f0;
      IPMI_lo_Logout(auStack_54);
      iVar12 = json_object_array_length(uVar10);
      iVar5 = 0;
      if (0 < iVar12) {
        do {
          json_object_array_get_idx(uVar10,iVar5);
          iVar5 = iVar5 + 1;
          json_object_put();
        } while (iVar12 != iVar5);
      }
      json_object_put(uVar10);
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        local_90 = json_object_new_object();
        uVar10 = json_object_new_string_len(DAT_0012f7c4,0x20);
        json_object_object_add(local_90,DAT_0012f770,uVar10);
        uVar10 = json_object_new_int(DAT_0012f7c8);
        json_object_object_add(local_90,DAT_0012f7b4,uVar10);
        uVar10 = DAT_0012f7cc;
LAB_0012f558:
        FCGI_printf(DAT_0012f7bc,uVar10);
        qcgires_setcontenttype(iVar2,DAT_0012f764);
        uVar10 = json_object_to_json_string(local_90);
        FCGI_printf(DAT_0012f774,uVar10);
      }
      else {
        iVar5 = strcasecmp(pcVar3,DAT_0012f784);
        pcVar7 = pcVar6;
        if (pcVar6 != (char *)0x0) {
          pcVar7 = (char *)0x1;
        }
        if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
           (iVar5 = strcasecmp(pcVar3,DAT_0012f7c0), iVar5 == 0)) {
          strncasecmp(pcVar6,DAT_0012f764,0x10);
        }
        if (local_90 != 0) {
          json_object_put(local_90);
        }
        iVar5 = json_object_new_object();
        uVar10 = json_object_new_string_len(DAT_0012f7c4,0x20);
        json_object_object_add(iVar5,DAT_0012f770,uVar10);
        uVar10 = json_object_new_int(DAT_0012f7c8);
        json_object_object_add(iVar5,DAT_0012f7b4,uVar10);
        FCGI_printf(DAT_0012f7bc,DAT_0012f7cc);
        qcgires_setcontenttype(iVar2,DAT_0012f764);
        uVar10 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0012f774,uVar10);
        if ((iVar5 != 0) && (json_object_put(iVar5), pcVar7 = pcVar6, pcVar6 != (char *)0x0)) {
          pcVar7 = (char *)0x1;
        }
        iVar5 = strcasecmp(pcVar3,DAT_0012f784);
        if (iVar5 == 0) {
          pcVar7 = (char *)0x0;
        }
joined_r0x0012f394:
        if (pcVar7 != (char *)0x0) goto LAB_0012f4a8;
      }
      if (local_90 != 0) {
        json_object_put(local_90);
      }
    }
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0012efe0:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

