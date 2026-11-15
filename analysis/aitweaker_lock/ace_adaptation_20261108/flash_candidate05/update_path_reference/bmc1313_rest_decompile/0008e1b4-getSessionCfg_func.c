
void getSessionCfg_func(void)

{
  char cVar1;
  undefined1 uVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  char *pcVar8;
  size_t sVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  void *__ptr;
  int iVar12;
  uint uVar13;
  undefined4 uVar14;
  void *pvVar15;
  uint uVar16;
  int local_e8;
  undefined1 *local_e0;
  void *local_d4;
  uint local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined1 local_b4;
  undefined1 auStack_b0 [44];
  undefined1 auStack_84 [44];
  char acStack_58 [7];
  undefined1 auStack_51 [45];
  
  iVar3 = qcgireq_parse(0);
  pcVar4 = getenv(DAT_0008f138);
  pre_call_hook(iVar3);
  iVar5 = qcgisess_init(iVar3,0);
  if (iVar5 == 0) {
    FCGI_printf(DAT_0008f148);
    FCGI_printf(DAT_0008f14c);
    qcgires_setcontenttype(iVar3,DAT_0008f1fc);
    uVar11 = json_object_new_object();
    uVar10 = json_object_new_int(7);
    json_object_object_add(uVar11,DAT_0008f150,uVar10);
    uVar10 = json_object_new_string(DAT_0008f154);
    json_object_object_add(uVar11,DAT_0008f158,uVar10);
    uVar10 = json_object_to_json_string(uVar11);
    FCGI_printf(DAT_0008f1d4,uVar10);
    json_object_put(uVar11);
    goto LAB_0008e32c;
  }
  iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_0008f13c);
  if (iVar6 == 1 && pcVar4 != (char *)0x0) {
    pcVar7 = (char *)(**(code **)(iVar5 + 0x18))(iVar5,DAT_0008f140,0);
    pcVar8 = (char *)(**(code **)(iVar5 + 0x18))(iVar5,DAT_0008f140,0);
    sVar9 = strlen(pcVar8);
    iVar6 = strncmp(pcVar7,pcVar4,sVar9);
    if ((iVar6 != 0) || (iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_0008f144), iVar6 != 0))
    goto LAB_0008e27c;
    pre_authorized_call_hook(iVar3,iVar5);
    uVar11 = json_object_new_array();
    __ptr = (void *)qcgireq_getquery(4);
    local_e8 = json_object_new_object();
    pcVar4 = getenv(DAT_0008f160);
    pcVar7 = getenv(DAT_0008f164);
    if ((pcVar4 != (char *)0x0) &&
       (iVar6 = strcasecmp(pcVar4,DAT_0008f168),
       iVar6 != 0 && (__ptr != (void *)0x0 && pcVar7 != (char *)0x0))) {
      json_object_put(local_e8);
      local_e8 = json_tokener_parse(__ptr);
    }
    if (*DAT_0008f16c == 0) {
LAB_0008e438:
      local_e0 = auStack_b0;
      local_d0 = 0;
      memset(acStack_58,0,0x2e);
      local_c0 = 0;
      local_bc = 0;
      local_b8 = 0;
      local_b4 = 0;
      local_cc = 0;
      local_c8 = 0;
      local_c4 = 0;
      iVar6 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0008f178);
      if (*(int *)(DAT_0008f17c + 0x54) == 1) {
        iVar12 = racsessinfo_getallrecords(&local_d4,auStack_84,&local_d0);
        if (iVar12 == 0) {
          pvVar15 = local_d4;
          if (iVar6 == 0x10) {
            if (local_d0 != 0) {
              uVar16 = 0;
              uVar13 = local_d0;
              do {
                iVar6 = uVar16 * 0x73;
                cVar1 = *(char *)((int)pvVar15 + iVar6 + 8);
                if (cVar1 == '\f' || cVar1 == '\t') {
                  snprintf(acStack_58,0x2e,DAT_0008f1d4,(int)pvVar15 + iVar6 + 9);
                  iVar12 = strncmp(acStack_58,DAT_0008f1c4,7);
                  if (iVar12 == 0) {
                    uVar13 = snprintf((char *)((int)local_d4 + iVar6 + 9),0x2e,DAT_0008f1d4,
                                      auStack_51);
                    uVar10 = DAT_0008f1d8;
                    if (0x2d < uVar13) goto LAB_0008f0fc;
                  }
                  else {
                    iVar12 = strncmp(acStack_58,DAT_0008f1c8,3);
                    if ((iVar12 == 0) || (iVar12 = strncmp(acStack_58,DAT_0008f1cc,9), iVar12 == 0))
                    {
                      memcpy((void *)((int)local_d4 + iVar6 + 9),DAT_0008f1d0,2);
                    }
                  }
                  uVar10 = json_object_new_object();
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                  json_object_object_add(uVar10,DAT_0008f1dc,uVar14);
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                  json_object_object_add(uVar10,DAT_0008f1e0,uVar14);
                  uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 8));
                  json_object_object_add(uVar10,DAT_0008f1e4,uVar14);
                  pcVar7 = (char *)((int)local_d4 + iVar6 + 9);
                  sVar9 = strlen(pcVar7);
                  uVar14 = json_object_new_string_len(pcVar7,sVar9);
                  json_object_object_add(uVar10,DAT_0008f1e8,uVar14);
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6 + 0x6b));
                  json_object_object_add(uVar10,DAT_0008f1ec,uVar14);
                  pcVar7 = (char *)((int)local_d4 + iVar6 + 0x39);
                  sVar9 = strlen(pcVar7);
                  uVar14 = json_object_new_string_len(pcVar7,sVar9);
                  json_object_object_add(uVar10,DAT_0008f1f0,uVar14);
                  uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 0x6a));
                  json_object_object_add(uVar10,DAT_0008f1f4,uVar14);
                  json_object_array_add(uVar11,uVar10);
                  uVar13 = local_d0;
                  pvVar15 = local_d4;
                }
                uVar16 = uVar16 + 1;
              } while (uVar16 < uVar13);
            }
          }
          else if (iVar6 < 0x11) {
            if (iVar6 == 2) {
              if (local_d0 != 0) {
                uVar16 = 0;
                uVar13 = local_d0;
                do {
                  iVar6 = uVar16 * 0x73;
                  uVar16 = uVar16 + 1;
                  if (*(char *)((int)pvVar15 + iVar6 + 8) == '\x05') {
                    uVar10 = json_object_new_object();
                    uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                    json_object_object_add(uVar10,DAT_0008f1dc,uVar14);
                    uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                    json_object_object_add(uVar10,DAT_0008f1e0,uVar14);
                    uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 8));
                    json_object_object_add(uVar10,DAT_0008f1e4,uVar14);
                    pcVar7 = (char *)((int)local_d4 + iVar6 + 9);
                    sVar9 = strlen(pcVar7);
                    uVar14 = json_object_new_string_len(pcVar7,sVar9);
                    json_object_object_add(uVar10,DAT_0008f1e8,uVar14);
                    uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6 + 0x6b));
                    json_object_object_add(uVar10,DAT_0008f1ec,uVar14);
                    pcVar7 = (char *)((int)local_d4 + iVar6 + 0x39);
                    sVar9 = strlen(pcVar7);
                    uVar14 = json_object_new_string_len(pcVar7,sVar9);
                    json_object_object_add(uVar10,DAT_0008f1f0,uVar14);
                    uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 0x6a));
                    json_object_object_add(uVar10,DAT_0008f1f4,uVar14);
                    json_object_array_add(uVar11,uVar10);
                    uVar13 = local_d0;
                    pvVar15 = local_d4;
                  }
                } while (uVar16 < uVar13);
              }
            }
            else if (iVar6 == 4) {
              if (local_d0 != 0) {
                uVar16 = 0;
                uVar13 = local_d0;
                do {
                  iVar6 = uVar16 * 0x73;
                  cVar1 = *(char *)((int)pvVar15 + iVar6 + 8);
                  if (cVar1 == '\n' || cVar1 == '\a') {
                    snprintf(acStack_58,0x2e,DAT_0008f1d4,(int)pvVar15 + iVar6 + 9);
                    iVar12 = strncmp(acStack_58,DAT_0008f1c4,7);
                    if (iVar12 == 0) {
                      uVar13 = snprintf((char *)((int)local_d4 + iVar6 + 9),0x2e,DAT_0008f1d4,
                                        auStack_51);
                      uVar10 = DAT_0008f1b4;
                      if (0x2d < uVar13) goto LAB_0008f0fc;
                    }
                    else {
                      iVar12 = strncmp(acStack_58,DAT_0008f1c8,3);
                      if ((iVar12 == 0) ||
                         (iVar12 = strncmp(acStack_58,DAT_0008f1cc,9), iVar12 == 0)) {
                        memcpy((void *)((int)local_d4 + iVar6 + 9),DAT_0008f1d0,2);
                      }
                    }
                    uVar10 = json_object_new_object();
                    uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                    json_object_object_add(uVar10,DAT_0008f1dc,uVar14);
                    uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                    json_object_object_add(uVar10,DAT_0008f1e0,uVar14);
                    uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 8));
                    json_object_object_add(uVar10,DAT_0008f1e4,uVar14);
                    pcVar7 = (char *)((int)local_d4 + iVar6 + 9);
                    sVar9 = strlen(pcVar7);
                    uVar14 = json_object_new_string_len(pcVar7,sVar9);
                    json_object_object_add(uVar10,DAT_0008f1e8,uVar14);
                    uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6 + 0x6b));
                    json_object_object_add(uVar10,DAT_0008f1ec,uVar14);
                    pcVar7 = (char *)((int)local_d4 + iVar6 + 0x39);
                    sVar9 = strlen(pcVar7);
                    uVar14 = json_object_new_string_len(pcVar7,sVar9);
                    json_object_object_add(uVar10,DAT_0008f1f0,uVar14);
                    uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 0x6a));
                    json_object_object_add(uVar10,DAT_0008f1f4,uVar14);
                    json_object_array_add(uVar11,uVar10);
                    uVar13 = local_d0;
                    pvVar15 = local_d4;
                  }
                  uVar16 = uVar16 + 1;
                } while (uVar16 < uVar13);
              }
            }
            else if ((iVar6 == 1) && (local_d0 != 0)) {
              uVar16 = 0;
              uVar13 = local_d0;
              do {
                iVar6 = uVar16 * 0x73;
                uVar16 = uVar16 + 1;
                if (*(byte *)((int)pvVar15 + iVar6 + 8) < 2) {
                  uVar10 = json_object_new_object();
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                  json_object_object_add(uVar10,DAT_0008f1dc,uVar14);
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                  json_object_object_add(uVar10,DAT_0008f1e0,uVar14);
                  uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 8));
                  json_object_object_add(uVar10,DAT_0008f1e4,uVar14);
                  pcVar7 = (char *)((int)local_d4 + iVar6 + 9);
                  sVar9 = strlen(pcVar7);
                  uVar14 = json_object_new_string_len(pcVar7,sVar9);
                  json_object_object_add(uVar10,DAT_0008f1e8,uVar14);
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6 + 0x6b));
                  json_object_object_add(uVar10,DAT_0008f1ec,uVar14);
                  pcVar7 = (char *)((int)local_d4 + iVar6 + 0x39);
                  sVar9 = strlen(pcVar7);
                  uVar14 = json_object_new_string_len(pcVar7,sVar9);
                  json_object_object_add(uVar10,DAT_0008f1f0,uVar14);
                  uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 0x6a));
                  json_object_object_add(uVar10,DAT_0008f1f4,uVar14);
                  json_object_array_add(uVar11,uVar10);
                  uVar13 = local_d0;
                  pvVar15 = local_d4;
                }
              } while (uVar16 < uVar13);
            }
          }
          else if (iVar6 == 0x40) {
            if (local_d0 != 0) {
              uVar16 = 0;
              uVar13 = local_d0;
              do {
                iVar6 = uVar16 * 0x73;
                uVar16 = uVar16 + 1;
                if (*(char *)((int)pvVar15 + iVar6 + 8) == '\x02') {
                  uVar10 = json_object_new_object();
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                  json_object_object_add(uVar10,DAT_0008f1dc,uVar14);
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                  json_object_object_add(uVar10,DAT_0008f1e0,uVar14);
                  uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 8));
                  json_object_object_add(uVar10,DAT_0008f1e4,uVar14);
                  pcVar7 = (char *)((int)local_d4 + iVar6 + 9);
                  sVar9 = strlen(pcVar7);
                  uVar14 = json_object_new_string_len(pcVar7,sVar9);
                  json_object_object_add(uVar10,DAT_0008f1e8,uVar14);
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6 + 0x6b));
                  json_object_object_add(uVar10,DAT_0008f1ec,uVar14);
                  pcVar7 = (char *)((int)local_d4 + iVar6 + 0x39);
                  sVar9 = strlen(pcVar7);
                  uVar14 = json_object_new_string_len(pcVar7,sVar9);
                  json_object_object_add(uVar10,DAT_0008f1f0,uVar14);
                  uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 0x6a));
                  json_object_object_add(uVar10,DAT_0008f1f4,uVar14);
                  json_object_array_add(uVar11,uVar10);
                  uVar13 = local_d0;
                  pvVar15 = local_d4;
                }
              } while (uVar16 < uVar13);
            }
          }
          else if (iVar6 < 0x41) {
            if (iVar6 == 0x20) goto LAB_0008ea44;
          }
          else if (iVar6 == 0x80) {
LAB_0008ea44:
            GetMacrodefine_string(DAT_0008f1a4,&local_cc);
            pvVar15 = local_d4;
            if (iVar6 == 0x20) {
              iVar6 = strcasecmp((char *)&local_cc,DAT_0008f200);
              pvVar15 = local_d4;
              if (iVar6 == 0) {
                iVar6 = IsFeatureEnabled(DAT_0008f204);
                pvVar15 = local_d4;
                goto joined_r0x0008f98c;
              }
            }
            else if (iVar6 == 0x80) {
              iVar6 = strcasecmp((char *)&local_cc,DAT_0008f200);
joined_r0x0008f98c:
              if (iVar6 != 0) goto LAB_0008e660;
            }
            if (local_d0 != 0) {
              uVar13 = 0;
              uVar16 = local_d0;
              do {
                iVar6 = uVar13 * 0x73;
                uVar13 = uVar13 + 1;
                if (*(char *)((int)pvVar15 + iVar6 + 8) == '\x03') {
                  uVar10 = json_object_new_object();
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                  json_object_object_add(uVar10,DAT_0008f1dc,uVar14);
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                  json_object_object_add(uVar10,DAT_0008f1e0,uVar14);
                  uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 8));
                  json_object_object_add(uVar10,DAT_0008f1e4,uVar14);
                  pcVar7 = (char *)((int)local_d4 + iVar6 + 9);
                  sVar9 = strlen(pcVar7);
                  uVar14 = json_object_new_string_len(pcVar7,sVar9);
                  json_object_object_add(uVar10,DAT_0008f1e8,uVar14);
                  uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6 + 0x6b));
                  json_object_object_add(uVar10,DAT_0008f1ec,uVar14);
                  pcVar7 = (char *)((int)local_d4 + iVar6 + 0x39);
                  sVar9 = strlen(pcVar7);
                  uVar14 = json_object_new_string_len(pcVar7,sVar9);
                  json_object_object_add(uVar10,DAT_0008f1f0,uVar14);
                  uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 0x6a));
                  json_object_object_add(uVar10,DAT_0008f1f4,uVar14);
                  json_object_array_add(uVar11,uVar10);
                  uVar16 = local_d0;
                  pvVar15 = local_d4;
                }
              } while (uVar13 < uVar16);
            }
          }
          else if ((iVar6 == 0x100) && (local_d0 != 0)) {
            uVar16 = 0;
            uVar13 = local_d0;
            do {
              iVar6 = uVar16 * 0x73;
              uVar16 = uVar16 + 1;
              if (*(char *)((int)pvVar15 + iVar6 + 8) == '\x0e') {
                uVar10 = json_object_new_object();
                uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                json_object_object_add(uVar10,DAT_0008f1dc,uVar14);
                uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6));
                json_object_object_add(uVar10,DAT_0008f1e0,uVar14);
                uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 8));
                json_object_object_add(uVar10,DAT_0008f1e4,uVar14);
                pcVar7 = (char *)((int)local_d4 + iVar6 + 9);
                sVar9 = strlen(pcVar7);
                uVar14 = json_object_new_string_len(pcVar7,sVar9);
                json_object_object_add(uVar10,DAT_0008f1e8,uVar14);
                uVar14 = json_object_new_int(*(undefined4 *)((int)local_d4 + iVar6 + 0x6b));
                json_object_object_add(uVar10,DAT_0008f1ec,uVar14);
                uVar14 = json_object_new_string_len(DAT_0008f1a0,3);
                json_object_object_add(uVar10,DAT_0008f1f0,uVar14);
                uVar14 = json_object_new_int(*(undefined1 *)((int)local_d4 + iVar6 + 0x6a));
                json_object_object_add(uVar10,DAT_0008f1f4,uVar14);
                json_object_array_add(uVar11,uVar10);
                uVar13 = local_d0;
                pvVar15 = local_d4;
              }
            } while (uVar16 < uVar13);
          }
LAB_0008e660:
          if (pvVar15 != (void *)0x0) {
            free(pvVar15);
          }
          qcgires_setcontenttype(iVar3,DAT_0008f1fc);
          uVar10 = json_object_to_json_string(uVar11);
          FCGI_printf(DAT_0008f1d4,uVar10);
          IPMI_lo_Logout(local_e0);
          iVar12 = json_object_array_length(uVar11);
          iVar6 = 0;
          if (0 < iVar12) {
            do {
              json_object_array_get_idx(uVar11,iVar6);
              iVar6 = iVar6 + 1;
              json_object_put();
            } while (iVar12 != iVar6);
          }
          json_object_put(uVar11);
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar4 != (char *)0x0) {
            strcasecmp(pcVar4,DAT_0008f168);
            goto LAB_0008e6f4;
          }
          goto LAB_0008e30c;
        }
        if (local_d4 != (void *)0x0) {
          free(local_d4);
        }
        IPMI_lo_Logout(local_e0);
        iVar12 = json_object_array_length(uVar11);
        iVar6 = 0;
        if (0 < iVar12) {
          do {
            json_object_array_get_idx(uVar11,iVar6);
            iVar6 = iVar6 + 1;
            json_object_put();
          } while (iVar12 != iVar6);
        }
        json_object_put(uVar11);
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar4 == (char *)0x0) {
          local_e8 = json_object_new_object();
          uVar11 = json_object_new_string_len(DAT_0008f194,0x1e);
          json_object_object_add(local_e8,DAT_0008f158,uVar11);
          uVar11 = json_object_new_int(DAT_0008f198);
          json_object_object_add(local_e8,DAT_0008f188,uVar11);
          uVar11 = DAT_0008f19c;
          goto LAB_0008ec80;
        }
        iVar6 = strcasecmp(pcVar4,DAT_0008f168);
        pcVar8 = pcVar7;
        if (pcVar7 != (char *)0x0) {
          pcVar8 = (char *)0x1;
        }
        if ((iVar6 != 0 && pcVar7 != (char *)0x0) &&
           (iVar6 = strcasecmp(pcVar4,DAT_0008f1f8), iVar6 == 0)) {
          strncasecmp(pcVar7,DAT_0008f1fc,0x10);
        }
        if (local_e8 != 0) {
          json_object_put(local_e8);
        }
        iVar6 = json_object_new_object();
        uVar11 = json_object_new_string_len(DAT_0008f194,0x1e);
        json_object_object_add(iVar6,DAT_0008f158,uVar11);
        uVar11 = json_object_new_int(DAT_0008f198);
        json_object_object_add(iVar6,DAT_0008f188,uVar11);
        FCGI_printf(DAT_0008f190,DAT_0008f19c);
        qcgires_setcontenttype(iVar3,DAT_0008f1fc);
        uVar11 = json_object_to_json_string(iVar6);
        FCGI_printf(DAT_0008f1d4,uVar11);
        if ((iVar6 != 0) && (json_object_put(iVar6), pcVar8 = pcVar7, pcVar7 != (char *)0x0)) {
          pcVar8 = (char *)0x1;
        }
        iVar6 = strcasecmp(pcVar4,DAT_0008f168);
        if (iVar6 == 0) {
          pcVar8 = (char *)0x0;
        }
        if (pcVar8 == (char *)0x0) goto LAB_0008e6f4;
      }
      else {
        IPMI_lo_Logout(local_e0);
        iVar12 = json_object_array_length(uVar11);
        iVar6 = 0;
        if (0 < iVar12) {
          do {
            json_object_array_get_idx(uVar11,iVar6);
            iVar6 = iVar6 + 1;
            json_object_put();
          } while (iVar12 != iVar6);
        }
        json_object_put(uVar11);
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar4 == (char *)0x0) {
          local_e8 = json_object_new_object();
          uVar11 = json_object_new_string_len(DAT_0008f180,0x16);
          json_object_object_add(local_e8,DAT_0008f158,uVar11);
          uVar11 = json_object_new_int(DAT_0008f184);
          json_object_object_add(local_e8,DAT_0008f188,uVar11);
          uVar11 = DAT_0008f18c;
LAB_0008ec80:
          FCGI_printf(DAT_0008f190,uVar11);
          qcgires_setcontenttype(iVar3,DAT_0008f1fc);
          uVar11 = json_object_to_json_string(local_e8);
          FCGI_printf(DAT_0008f1d4,uVar11);
        }
        else {
          iVar6 = strcasecmp(pcVar4,DAT_0008f168);
          if ((iVar6 != 0 && pcVar7 != (char *)0x0) &&
             (iVar6 = strcasecmp(pcVar4,DAT_0008f1f8), iVar6 == 0)) {
            strncasecmp(pcVar7,DAT_0008f1fc,0x10);
          }
          if (local_e8 != 0) {
            json_object_put(local_e8);
          }
          iVar6 = json_object_new_object();
          uVar11 = json_object_new_string_len(DAT_0008f180,0x16);
          json_object_object_add(iVar6,DAT_0008f158,uVar11);
          uVar11 = json_object_new_int(DAT_0008f184);
          json_object_object_add(iVar6,DAT_0008f188,uVar11);
          FCGI_printf(DAT_0008f190,DAT_0008f18c);
          qcgires_setcontenttype(iVar3,DAT_0008f1fc);
          uVar11 = json_object_to_json_string(iVar6);
          FCGI_printf(DAT_0008f1d4,uVar11);
          if (iVar6 != 0) {
            json_object_put(iVar6);
          }
          strcasecmp(pcVar4,DAT_0008f168);
        }
      }
joined_r0x0008ecac:
      if (local_e8 != 0) {
        json_object_put(local_e8);
      }
    }
    else {
      uVar2 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_0008f170);
      iVar6 = IPMI_lo_Login(DAT_0008f174,DAT_0008f174,auStack_b0,uVar2,1,0,0,0);
      if (iVar6 == 0) goto LAB_0008e438;
      IPMI_lo_Logout(auStack_b0);
      iVar12 = json_object_array_length(uVar11);
      iVar6 = 0;
      if (0 < iVar12) {
        do {
          json_object_array_get_idx(uVar11,iVar6);
          iVar6 = iVar6 + 1;
          json_object_put();
        } while (iVar12 != iVar6);
      }
      json_object_put(uVar11);
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar4 == (char *)0x0) {
        local_e8 = json_object_new_object();
        uVar11 = json_object_new_string_len(DAT_0008f1a8,0x20);
        json_object_object_add(local_e8,DAT_0008f158,uVar11);
        uVar11 = json_object_new_int(DAT_0008f1ac);
        json_object_object_add(local_e8,DAT_0008f188,uVar11);
        uVar11 = DAT_0008f1b0;
        goto LAB_0008ec80;
      }
      iVar6 = strcasecmp(pcVar4,DAT_0008f168);
      pcVar8 = pcVar7;
      if (pcVar7 != (char *)0x0) {
        pcVar8 = (char *)0x1;
      }
      if ((iVar6 != 0 && pcVar7 != (char *)0x0) &&
         (iVar6 = strcasecmp(pcVar4,DAT_0008f1f8), iVar6 == 0)) {
        strncasecmp(pcVar7,DAT_0008f1fc,0x10);
      }
      if (local_e8 != 0) {
        json_object_put(local_e8);
      }
      iVar6 = json_object_new_object();
      uVar11 = json_object_new_string_len(DAT_0008f1a8,0x20);
      json_object_object_add(iVar6,DAT_0008f158,uVar11);
      uVar11 = json_object_new_int(DAT_0008f1ac);
      json_object_object_add(iVar6,DAT_0008f188,uVar11);
      FCGI_printf(DAT_0008f190,DAT_0008f1b0);
      qcgires_setcontenttype(iVar3,DAT_0008f1fc);
      uVar11 = json_object_to_json_string(iVar6);
      FCGI_printf(DAT_0008f1d4,uVar11);
      if ((iVar6 != 0) && (json_object_put(iVar6), pcVar8 = pcVar7, pcVar7 != (char *)0x0)) {
        pcVar8 = (char *)0x1;
      }
      iVar6 = strcasecmp(pcVar4,DAT_0008f168);
      if (iVar6 == 0) {
        pcVar8 = (char *)0x0;
      }
      if (pcVar8 == (char *)0x0) goto joined_r0x0008ecac;
LAB_0008e6f4:
      if (local_e8 != 0) {
        json_object_put(local_e8);
      }
    }
  }
  else {
LAB_0008e27c:
    FCGI_printf(DAT_0008f148);
    FCGI_printf(DAT_0008f14c);
    qcgires_setcontenttype(iVar3,DAT_0008f1fc);
    uVar10 = json_object_new_object();
    uVar11 = json_object_new_int(7);
    json_object_object_add(uVar10,DAT_0008f150,uVar11);
    iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_0008f144);
    uVar11 = DAT_0008f154;
    if (iVar6 == 1) {
      uVar11 = DAT_0008f15c;
    }
    uVar11 = json_object_new_string(uVar11);
    json_object_object_add(uVar10,DAT_0008f158,uVar11);
    uVar11 = json_object_to_json_string(uVar10);
    FCGI_printf(DAT_0008f1d4,uVar11);
    json_object_put(uVar10);
    qcgisess_clear(iVar5);
  }
LAB_0008e30c:
  post_authorized_call_hook(iVar3,iVar5);
  qcgisess_save(iVar5);
  (**(code **)(iVar5 + 0x58))(iVar5);
LAB_0008e32c:
  post_call_hook(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
  return;
LAB_0008f0fc:
  IDBG_LINUXAPP_DbgOut(0x82,DAT_0008f1bc,DAT_0008f1c0,uVar10,DAT_0008f1b8,uVar10);
  pvVar15 = local_d4;
  goto LAB_0008e660;
}

