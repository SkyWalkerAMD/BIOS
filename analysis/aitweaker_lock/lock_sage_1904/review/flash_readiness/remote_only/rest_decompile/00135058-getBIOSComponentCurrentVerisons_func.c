
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
  pcVar3 = getenv(DAT_0013593c);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0013594c);
    FCGI_printf(DAT_00135950);
    qcgires_setcontenttype(iVar2,DAT_00135954);
    uVar10 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar10,DAT_00135958,uVar9);
    uVar9 = json_object_new_string(DAT_0013595c);
    json_object_object_add(uVar10,DAT_00135960,uVar9);
    uVar9 = json_object_to_json_string(uVar10);
    FCGI_printf(DAT_00135964,uVar9);
    json_object_put(uVar10);
    goto LAB_001351d0;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00135940);
  if (pcVar3 == (char *)0x0 || iVar5 != 1) {
LAB_00135120:
    FCGI_printf(DAT_0013594c);
    FCGI_printf(DAT_00135950);
    qcgires_setcontenttype(iVar2,DAT_00135954);
    uVar9 = json_object_new_object();
    uVar10 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_00135958,uVar10);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00135948);
    uVar10 = DAT_0013595c;
    if (iVar5 == 1) {
      uVar10 = DAT_00135968;
    }
    uVar10 = json_object_new_string(uVar10);
    json_object_object_add(uVar9,DAT_00135960,uVar10);
    uVar10 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_00135964,uVar10);
    json_object_put(uVar9);
    qcgisess_clear(iVar4);
  }
  else {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00135944,0);
    pcVar7 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00135944,0);
    sVar8 = strlen(pcVar7);
    iVar5 = strncmp(pcVar6,pcVar3,sVar8);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00135948), iVar5 != 0))
    goto LAB_00135120;
    pre_authorized_call_hook(iVar2,iVar4);
    uVar10 = json_object_new_array();
    __ptr = (void *)qcgireq_getquery(4);
    local_90 = json_object_new_object();
    pcVar3 = getenv(DAT_0013596c);
    pcVar6 = getenv(DAT_00135970);
    if ((pcVar3 != (char *)0x0) &&
       (iVar5 = strcasecmp(pcVar3,DAT_00135974),
       iVar5 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(local_90);
      local_90 = json_tokener_parse(__ptr);
    }
    if (*DAT_00135978 == 0) {
LAB_001352e0:
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
      uVar9 = (**(code **)(iVar2 + 0x18))(iVar2,DAT_00135984,0);
      snprintf((char *)&local_74,10,DAT_00135964,uVar9);
      pcVar7 = strsep(&local_80,DAT_00135988);
      if (pcVar7 != (char *)0x0) {
        do {
          local_7c = 0;
          local_78 = 0;
          uVar11 = strtol(pcVar7,(char **)0x0,10);
          iVar5 = LIBIPMI_HL_GetCompProperties_CurrVersion(local_98,uVar11 & 0xff,&local_7c,0x3c);
          snprintf((char *)&local_68,0x14,DAT_0013598c,local_7c >> 0x10 & 0xff,local_7c >> 0x18,
                   local_78);
          iVar12 = json_object_new_object();
          uVar9 = json_object_new_int(cVar13);
          json_object_object_add(iVar12,DAT_00135990,uVar9);
          sVar8 = strlen(pcVar7);
          uVar9 = json_object_new_string_len(pcVar7,sVar8);
          json_object_object_add(iVar12,DAT_00135994,uVar9);
          sVar8 = strlen((char *)&local_68);
          uVar9 = json_object_new_string_len(&local_68,sVar8);
          json_object_object_add(iVar12,DAT_00135998,uVar9);
          json_object_array_add(uVar10,iVar12);
          pcVar7 = strsep(&local_80,DAT_00135988);
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
            iVar5 = strcasecmp(pcVar3,DAT_00135974);
            pcVar7 = pcVar6;
            if (pcVar6 != (char *)0x0) {
              pcVar7 = (char *)0x1;
            }
            if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
               (iVar5 = strcasecmp(pcVar3,DAT_001359b0), iVar5 == 0)) {
              strncasecmp(pcVar6,DAT_00135954,0x10);
            }
            if (local_90 != 0) {
              json_object_put(local_90);
            }
            iVar5 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_0013599c,0x1f);
            json_object_object_add(iVar5,DAT_00135960,uVar10);
            uVar10 = json_object_new_int(DAT_001359a0);
            json_object_object_add(iVar5,DAT_001359a4,uVar10);
            FCGI_printf(DAT_001359ac,DAT_001359a8);
            qcgires_setcontenttype(iVar2,DAT_00135954);
            uVar10 = json_object_to_json_string(iVar5);
            FCGI_printf(DAT_00135964,uVar10);
            if ((iVar5 != 0) && (json_object_put(iVar5), pcVar7 = pcVar6, pcVar6 != (char *)0x0)) {
              pcVar7 = (char *)0x1;
            }
            iVar5 = strcasecmp(pcVar3,DAT_00135974);
            if (iVar5 == 0) {
              pcVar7 = (char *)0x0;
            }
            if ((pcVar7 != (char *)0x0) && (iVar5 = strcasecmp(pcVar3,DAT_001359b0), iVar5 == 0)) {
              pcVar7 = (char *)strncasecmp(pcVar6,DAT_00135954,0x10);
              goto joined_r0x00135584;
            }
            goto LAB_00135698;
          }
          local_90 = json_object_new_object();
          uVar10 = json_object_new_string_len(DAT_0013599c,0x1f);
          json_object_object_add(local_90,DAT_00135960,uVar10);
          uVar10 = json_object_new_int(DAT_001359a0);
          json_object_object_add(local_90,DAT_001359a4,uVar10);
          uVar10 = DAT_001359a8;
          goto LAB_00135748;
        }
      }
      qcgires_setcontenttype(iVar2,DAT_00135954);
      uVar9 = json_object_to_json_string(uVar10);
      FCGI_printf(DAT_00135964,uVar9);
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
        strcasecmp(pcVar3,DAT_00135974);
LAB_00135698:
        if (local_90 != 0) {
          json_object_put(local_90);
        }
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0013597c);
      iVar5 = IPMI_lo_Login(DAT_00135980,DAT_00135980,auStack_54,uVar1,1,0,0,0);
      if (iVar5 == 0) goto LAB_001352e0;
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
        uVar10 = json_object_new_string_len(DAT_001359b4,0x20);
        json_object_object_add(local_90,DAT_00135960,uVar10);
        uVar10 = json_object_new_int(DAT_001359b8);
        json_object_object_add(local_90,DAT_001359a4,uVar10);
        uVar10 = DAT_001359bc;
LAB_00135748:
        FCGI_printf(DAT_001359ac,uVar10);
        qcgires_setcontenttype(iVar2,DAT_00135954);
        uVar10 = json_object_to_json_string(local_90);
        FCGI_printf(DAT_00135964,uVar10);
      }
      else {
        iVar5 = strcasecmp(pcVar3,DAT_00135974);
        pcVar7 = pcVar6;
        if (pcVar6 != (char *)0x0) {
          pcVar7 = (char *)0x1;
        }
        if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
           (iVar5 = strcasecmp(pcVar3,DAT_001359b0), iVar5 == 0)) {
          strncasecmp(pcVar6,DAT_00135954,0x10);
        }
        if (local_90 != 0) {
          json_object_put(local_90);
        }
        iVar5 = json_object_new_object();
        uVar10 = json_object_new_string_len(DAT_001359b4,0x20);
        json_object_object_add(iVar5,DAT_00135960,uVar10);
        uVar10 = json_object_new_int(DAT_001359b8);
        json_object_object_add(iVar5,DAT_001359a4,uVar10);
        FCGI_printf(DAT_001359ac,DAT_001359bc);
        qcgires_setcontenttype(iVar2,DAT_00135954);
        uVar10 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00135964,uVar10);
        if ((iVar5 != 0) && (json_object_put(iVar5), pcVar7 = pcVar6, pcVar6 != (char *)0x0)) {
          pcVar7 = (char *)0x1;
        }
        iVar5 = strcasecmp(pcVar3,DAT_00135974);
        if (iVar5 == 0) {
          pcVar7 = (char *)0x0;
        }
joined_r0x00135584:
        if (pcVar7 != (char *)0x0) goto LAB_00135698;
      }
      if (local_90 != 0) {
        json_object_put(local_90);
      }
    }
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_001351d0:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

