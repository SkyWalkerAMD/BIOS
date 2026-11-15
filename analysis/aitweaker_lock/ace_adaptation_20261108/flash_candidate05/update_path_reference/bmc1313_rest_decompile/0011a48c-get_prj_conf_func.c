
void get_prj_conf_func(void)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  bool bVar6;
  undefined1 uVar7;
  int iVar8;
  char *pcVar9;
  int iVar10;
  int iVar11;
  char *pcVar12;
  char *__s;
  size_t sVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  void *__ptr;
  int iVar16;
  undefined4 uVar17;
  bool bVar18;
  byte bVar19;
  int local_27c;
  undefined1 *local_274;
  undefined1 auStack_254 [44];
  char acStack_228 [256];
  char local_128 [260];
  
  iVar8 = qcgireq_parse(0);
  pcVar9 = getenv(DAT_0011ae68);
  pre_call_hook(iVar8);
  iVar10 = qcgisess_init(iVar8,0);
  if (iVar10 == 0) {
    FCGI_printf(DAT_0011ae78);
    FCGI_printf(DAT_0011ae7c);
    qcgires_setcontenttype(iVar8,DAT_0011ae80);
    uVar15 = json_object_new_object();
    uVar14 = json_object_new_int(7);
    json_object_object_add(uVar15,DAT_0011ae84,uVar14);
    uVar14 = json_object_new_string(DAT_0011ae88);
    json_object_object_add(uVar15,DAT_0011ae8c,uVar14);
    uVar14 = json_object_to_json_string(uVar15);
    FCGI_printf(DAT_0011ae90,uVar14);
    json_object_put(uVar15);
    goto LAB_0011a604;
  }
  iVar11 = (**(code **)(iVar10 + 0x24))(iVar10,DAT_0011ae6c);
  if (pcVar9 == (char *)0x0 || iVar11 != 1) {
LAB_0011a554:
    FCGI_printf(DAT_0011ae78);
    FCGI_printf(DAT_0011ae7c);
    qcgires_setcontenttype(iVar8,DAT_0011ae80);
    uVar14 = json_object_new_object();
    uVar15 = json_object_new_int(7);
    json_object_object_add(uVar14,DAT_0011ae84,uVar15);
    iVar11 = (**(code **)(iVar10 + 0x24))(iVar10,DAT_0011ae74);
    uVar15 = DAT_0011ae88;
    if (iVar11 == 1) {
      uVar15 = DAT_0011ae94;
    }
    uVar15 = json_object_new_string(uVar15);
    json_object_object_add(uVar14,DAT_0011ae8c,uVar15);
    uVar15 = json_object_to_json_string(uVar14);
    FCGI_printf(DAT_0011ae90,uVar15);
    json_object_put(uVar14);
    qcgisess_clear(iVar10);
  }
  else {
    pcVar12 = (char *)(**(code **)(iVar10 + 0x18))(iVar10,DAT_0011ae70,0);
    __s = (char *)(**(code **)(iVar10 + 0x18))(iVar10,DAT_0011ae70,0);
    sVar13 = strlen(__s);
    iVar11 = strncmp(pcVar12,pcVar9,sVar13);
    if ((iVar11 != 0) || (iVar11 = (**(code **)(iVar10 + 0x24))(iVar10,DAT_0011ae74), iVar11 != 0))
    goto LAB_0011a554;
    pre_authorized_call_hook(iVar8,iVar10);
    uVar15 = json_object_new_array();
    __ptr = (void *)qcgireq_getquery(4);
    local_27c = json_object_new_object();
    pcVar9 = getenv(DAT_0011ae98);
    pcVar12 = getenv(DAT_0011ae9c);
    if ((pcVar9 != (char *)0x0) &&
       (iVar11 = strcasecmp(pcVar9,DAT_0011aea0),
       iVar11 != 0 && (__ptr != (void *)0x0 && pcVar12 != (char *)0x0))) {
      json_object_put(local_27c);
      local_27c = json_tokener_parse(__ptr);
    }
    if (*DAT_0011aea4 == 0) {
LAB_0011a710:
      local_274 = auStack_254;
      iVar11 = FCGI_fopen(DAT_0011aeb4,DAT_0011aeb0);
      if (iVar11 == 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0011af24,DAT_0011af20,0xa1);
      }
      else {
        bVar1 = false;
        bVar6 = false;
        bVar19 = 0;
        bVar3 = false;
        bVar5 = false;
        bVar4 = false;
        bVar2 = false;
        while (iVar16 = FCGI_fgets(acStack_228,0x100,iVar11), iVar16 != 0) {
          pcVar12 = strchr(acStack_228,0x3d);
          if (pcVar12 != (char *)0x0) {
            memset(local_128,0,0x100);
            __isoc99_sscanf(pcVar12,DAT_0011aebc,local_128);
            if (local_128[0] != '\0') {
              iVar16 = strncmp(local_128,DAT_0011aec0,0xd);
              if (iVar16 == 0) {
                bVar2 = true;
              }
              else {
                iVar16 = strncmp(local_128,DAT_0011aec4,0xd);
                if (iVar16 == 0) {
                  bVar2 = true;
                }
              }
              iVar16 = strncmp(local_128,DAT_0011aec8,0xf);
              if (iVar16 == 0) {
                bVar3 = true;
              }
              iVar16 = strncmp(local_128,DAT_0011aecc,0x11);
              if (iVar16 == 0) {
                bVar6 = true;
              }
              iVar16 = strncmp(local_128,DAT_0011aed0,0x1a);
              if (iVar16 == 0) {
                bVar19 = 1;
              }
              iVar16 = strncmp(local_128,DAT_0011aed4,10);
              if ((iVar16 == 0) || (iVar16 = strncmp(local_128,DAT_0011aed8,0xe), iVar16 == 0)) {
                bVar4 = true;
              }
              else {
                iVar16 = strncmp(local_128,DAT_0011aedc,0xc);
                if (iVar16 == 0) {
                  bVar4 = true;
                }
              }
              iVar16 = strncmp(local_128,DAT_0011aee0,0xd);
              if (iVar16 == 0) {
                bVar5 = true;
              }
              else {
                iVar16 = strncmp(local_128,DAT_0011aee4,7);
                if (iVar16 == 0) {
                  bVar5 = true;
                }
              }
              iVar16 = strncmp(local_128,DAT_0011aee8,0x1a);
              if (iVar16 == 0) {
                bVar1 = true;
              }
              uVar14 = json_object_new_object();
              sVar13 = strlen(local_128);
              uVar17 = json_object_new_string_len(local_128,sVar13);
              json_object_object_add(uVar14,DAT_0011aeec,uVar17);
              json_object_array_add(uVar15,uVar14);
            }
          }
        }
        if (bVar2) {
          bVar18 = (bool)(bVar3 | bVar19);
        }
        else {
          uVar14 = json_object_new_object();
          uVar17 = json_object_new_string_len(DAT_0011aef0,0x1a);
          json_object_object_add(uVar14,DAT_0011aeec,uVar17);
          json_object_array_add(uVar15,uVar14);
          bVar18 = bVar3;
        }
        if (bVar18) {
          uVar14 = json_object_new_object();
          uVar17 = json_object_new_string_len(DAT_0011aef4,0x16);
          json_object_object_add(uVar14,DAT_0011aeec,uVar17);
          json_object_array_add(uVar15,uVar14);
        }
        if (!bVar4) {
          uVar14 = json_object_new_object();
          uVar17 = json_object_new_string_len(DAT_0011af18,0x1c);
          json_object_object_add(uVar14,DAT_0011aeec,uVar17);
          json_object_array_add(uVar15,uVar14);
        }
        if (!bVar5) {
          uVar14 = json_object_new_object();
          uVar17 = json_object_new_string_len(DAT_0011af14,0x1e);
          json_object_object_add(uVar14,DAT_0011aeec,uVar17);
          json_object_array_add(uVar15,uVar14);
        }
        if ((!bVar2 && !bVar3) && !bVar6) {
          uVar14 = json_object_new_object();
          uVar17 = json_object_new_string_len(DAT_0011af10,0x1a);
          json_object_object_add(uVar14,DAT_0011aeec,uVar17);
          json_object_array_add(uVar15,uVar14);
        }
        if ((*(int *)(DAT_0011aeb8 + 0x394) == 1) || (*(int *)(DAT_0011aeb8 + 0x3d8) == 1)) {
          uVar14 = json_object_new_object();
          uVar17 = json_object_new_string_len(DAT_0011aef8,0x14);
          json_object_object_add(uVar14,DAT_0011aeec,uVar17);
          json_object_array_add(uVar15,uVar14);
        }
        if (*(int *)(DAT_0011aeb8 + 0x200) == 1) {
          uVar14 = json_object_new_object();
          uVar17 = json_object_new_string_len(DAT_0011af28,0x17);
          json_object_object_add(uVar14,DAT_0011aeec,uVar17);
          json_object_array_add(uVar15,uVar14);
        }
        if (!bVar1) {
          uVar14 = json_object_new_object();
          uVar17 = json_object_new_string_len(DAT_0011af1c,0x1b);
          json_object_object_add(uVar14,DAT_0011aeec,uVar17);
          json_object_array_add(uVar15,uVar14);
        }
        FCGI_fclose(iVar11);
      }
      qcgires_setcontenttype(iVar8,DAT_0011ae80);
      uVar14 = json_object_to_json_string(uVar15);
      FCGI_printf(DAT_0011ae90,uVar14);
      IPMI_lo_Logout(local_274);
      iVar16 = json_object_array_length(uVar15);
      iVar11 = 0;
      if (0 < iVar16) {
        do {
          json_object_array_get_idx(uVar15,iVar11);
          iVar11 = iVar11 + 1;
          json_object_put();
        } while (iVar16 != iVar11);
      }
      json_object_put(uVar15);
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar9 != (char *)0x0) {
        strcasecmp(pcVar9,DAT_0011aea0);
LAB_0011a87c:
        if (local_27c != 0) {
          json_object_put(local_27c);
        }
      }
    }
    else {
      uVar7 = (**(code **)(iVar10 + 0x24))(iVar10,DAT_0011aea8);
      iVar11 = IPMI_lo_Login(DAT_0011aeac,DAT_0011aeac,auStack_254,uVar7,1,0,0,0);
      if (iVar11 == 0) goto LAB_0011a710;
      IPMI_lo_Logout(auStack_254);
      iVar16 = json_object_array_length(uVar15);
      iVar11 = 0;
      if (0 < iVar16) {
        do {
          json_object_array_get_idx(uVar15,iVar11);
          iVar11 = iVar11 + 1;
          json_object_put();
        } while (iVar16 != iVar11);
      }
      json_object_put(uVar15);
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar9 != (char *)0x0) {
        iVar11 = strcasecmp(pcVar9,DAT_0011aea0);
        if ((iVar11 != 0 && pcVar12 != (char *)0x0) &&
           (iVar11 = strcasecmp(pcVar9,DAT_0011af2c), iVar11 == 0)) {
          strncasecmp(pcVar12,DAT_0011ae80,0x10);
        }
        if (local_27c != 0) {
          json_object_put(local_27c);
        }
        iVar11 = json_object_new_object();
        uVar15 = json_object_new_string_len(DAT_0011aefc,0x20);
        json_object_object_add(iVar11,DAT_0011ae8c,uVar15);
        uVar15 = json_object_new_int(DAT_0011af00);
        json_object_object_add(iVar11,DAT_0011af04,uVar15);
        FCGI_printf(DAT_0011af0c,DAT_0011af08);
        qcgires_setcontenttype(iVar8,DAT_0011ae80);
        uVar15 = json_object_to_json_string(iVar11);
        FCGI_printf(DAT_0011ae90,uVar15);
        if (iVar11 != 0) {
          json_object_put(iVar11);
        }
        strcasecmp(pcVar9,DAT_0011aea0);
        goto LAB_0011a87c;
      }
      iVar11 = json_object_new_object();
      uVar15 = json_object_new_string_len(DAT_0011aefc,0x20);
      json_object_object_add(iVar11,DAT_0011ae8c,uVar15);
      uVar15 = json_object_new_int(DAT_0011af00);
      json_object_object_add(iVar11,DAT_0011af04,uVar15);
      FCGI_printf(DAT_0011af0c,DAT_0011af08);
      qcgires_setcontenttype(iVar8,DAT_0011ae80);
      uVar15 = json_object_to_json_string(iVar11);
      FCGI_printf(DAT_0011ae90,uVar15);
      if (iVar11 != 0) {
        json_object_put(iVar11);
      }
    }
  }
  post_authorized_call_hook(iVar8,iVar10);
  qcgisess_save(iVar10);
  (**(code **)(iVar10 + 0x58))(iVar10);
LAB_0011a604:
  post_call_hook(iVar8);
  (**(code **)(iVar8 + 0x58))(iVar8);
  return;
}

