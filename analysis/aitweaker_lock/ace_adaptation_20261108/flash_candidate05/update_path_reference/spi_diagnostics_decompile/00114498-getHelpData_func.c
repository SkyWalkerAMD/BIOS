
void getHelpData_func(void)

{
  undefined4 *puVar1;
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
  int iVar13;
  undefined4 uVar14;
  undefined4 *puVar15;
  undefined1 *local_b4;
  undefined1 auStack_ac [44];
  stat sStack_80;
  
  iVar3 = qcgireq_parse(0);
  pcVar4 = getenv(DAT_00114b04);
  pre_call_hook(iVar3);
  iVar5 = qcgisess_init(iVar3,0);
  if (iVar5 == 0) {
    FCGI_printf(DAT_00114b14);
    FCGI_printf(DAT_00114b18);
    qcgires_setcontenttype(iVar3,DAT_00114b1c);
    uVar11 = json_object_new_object();
    uVar10 = json_object_new_int(7);
    json_object_object_add(uVar11,DAT_00114b20,uVar10);
    uVar10 = json_object_new_string(DAT_00114b24);
    json_object_object_add(uVar11,DAT_00114b28,uVar10);
    uVar10 = json_object_to_json_string(uVar11);
    FCGI_printf(DAT_00114b2c,uVar10);
    json_object_put(uVar11);
    goto LAB_00114610;
  }
  iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_00114b08);
  if (iVar6 == 1 && pcVar4 != (char *)0x0) {
    pcVar7 = (char *)(**(code **)(iVar5 + 0x18))(iVar5,DAT_00114b0c,0);
    pcVar8 = (char *)(**(code **)(iVar5 + 0x18))(iVar5,DAT_00114b0c,0);
    sVar9 = strlen(pcVar8);
    iVar6 = strncmp(pcVar7,pcVar4,sVar9);
    if ((iVar6 != 0) || (iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_00114b10), iVar6 != 0))
    goto LAB_00114560;
    pre_authorized_call_hook(iVar3,iVar5);
    iVar6 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar12 = json_object_new_object();
    pcVar4 = getenv(DAT_00114b34);
    pcVar7 = getenv(DAT_00114b38);
    if ((pcVar4 != (char *)0x0) &&
       (iVar13 = strcasecmp(pcVar4,DAT_00114b3c),
       iVar13 != 0 && (pcVar7 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(iVar12);
      iVar12 = json_tokener_parse(__ptr);
    }
    if (*DAT_00114b40 == 0) {
LAB_00114714:
      local_b4 = auStack_ac;
      pcVar7 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_00114b4c,0);
      iVar13 = isValidFilename();
      if (iVar13 == 0) {
        sVar9 = strlen(pcVar7);
        pcVar8 = malloc(sVar9 + 0x18);
        puVar1 = DAT_00114b50;
        if (pcVar8 != (char *)0x0) {
          uVar11 = DAT_00114b50[1];
          uVar10 = DAT_00114b50[2];
          uVar14 = DAT_00114b50[3];
          puVar15 = DAT_00114b50 + 4;
          *(undefined4 *)pcVar8 = *DAT_00114b50;
          *(undefined4 *)(pcVar8 + 4) = uVar11;
          *(undefined4 *)(pcVar8 + 8) = uVar10;
          *(undefined4 *)(pcVar8 + 0xc) = uVar14;
          uVar11 = puVar1[5];
          *(undefined4 *)(pcVar8 + 0x10) = *puVar15;
          *(undefined4 *)(pcVar8 + 0x14) = uVar11;
          strcpy(pcVar8 + 0x17,pcVar7);
          iVar13 = __xstat(3,pcVar8,&sStack_80);
          if (iVar13 < 0) {
            free(pcVar8);
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00114b60,DAT_00114b5c,0xf1);
            goto LAB_0011489c;
          }
        }
        FCGI_printf(DAT_00114b54);
        FCGI_printf(DAT_00114b58,pcVar8);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar4 == (char *)0x0) {
          IPMI_lo_Logout(local_b4);
          if (iVar6 != 0) {
            json_object_put(iVar6);
          }
          goto LAB_001145f0;
        }
        strcasecmp(pcVar4,DAT_00114b3c);
        if (iVar12 != 0) {
          json_object_put(iVar12);
        }
        IPMI_lo_Logout(local_b4);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        strcasecmp(pcVar4,DAT_00114b3c);
      }
      else {
LAB_0011489c:
        IPMI_lo_Logout(local_b4);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar4 == (char *)0x0) {
          iVar6 = json_object_new_object();
          uVar11 = json_object_new_string_len(DAT_00114b64,0xd);
          json_object_object_add(iVar6,DAT_00114b28,uVar11);
          uVar11 = json_object_new_int(1);
          json_object_object_add(iVar6,DAT_00114b68,uVar11);
          uVar11 = DAT_00114b64;
          goto LAB_001149c0;
        }
        strcasecmp(pcVar4,DAT_00114b3c);
        if (iVar12 != 0) {
          json_object_put(iVar12);
        }
        iVar6 = json_object_new_object();
        uVar11 = json_object_new_string_len(DAT_00114b64,0xd);
        json_object_object_add(iVar6,DAT_00114b28,uVar11);
        uVar11 = json_object_new_int(1);
        json_object_object_add(iVar6,DAT_00114b68,uVar11);
        uVar11 = DAT_00114b64;
LAB_00114928:
        FCGI_printf(DAT_00114b6c,uVar11);
        qcgires_setcontenttype(iVar3,DAT_00114b1c);
        uVar11 = json_object_to_json_string(iVar6);
        FCGI_printf(DAT_00114b2c,uVar11);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        strcasecmp(pcVar4,DAT_00114b3c);
      }
      if (iVar12 != 0) {
        json_object_put(iVar12);
      }
    }
    else {
      uVar2 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_00114b44);
      iVar13 = IPMI_lo_Login(DAT_00114b48,DAT_00114b48,auStack_ac,uVar2,1,0,0,0);
      if (iVar13 == 0) goto LAB_00114714;
      IPMI_lo_Logout(auStack_ac);
      if (iVar6 != 0) {
        json_object_put(iVar6);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar4 != (char *)0x0) {
        strcasecmp(pcVar4,DAT_00114b3c);
        if (iVar12 != 0) {
          json_object_put(iVar12);
        }
        iVar6 = json_object_new_object();
        uVar11 = json_object_new_string_len(DAT_00114b70,0x20);
        json_object_object_add(iVar6,DAT_00114b28,uVar11);
        uVar11 = json_object_new_int(DAT_00114b74);
        json_object_object_add(iVar6,DAT_00114b68,uVar11);
        uVar11 = DAT_00114b78;
        goto LAB_00114928;
      }
      iVar6 = json_object_new_object();
      uVar11 = json_object_new_string_len(DAT_00114b70,0x20);
      json_object_object_add(iVar6,DAT_00114b28,uVar11);
      uVar11 = json_object_new_int(DAT_00114b74);
      json_object_object_add(iVar6,DAT_00114b68,uVar11);
      uVar11 = DAT_00114b78;
LAB_001149c0:
      FCGI_printf(DAT_00114b6c,uVar11);
      qcgires_setcontenttype(iVar3,DAT_00114b1c);
      uVar11 = json_object_to_json_string(iVar6);
      FCGI_printf(DAT_00114b2c,uVar11);
      if (iVar6 != 0) {
        json_object_put(iVar6);
      }
    }
  }
  else {
LAB_00114560:
    FCGI_printf(DAT_00114b14);
    FCGI_printf(DAT_00114b18);
    qcgires_setcontenttype(iVar3,DAT_00114b1c);
    uVar10 = json_object_new_object();
    uVar11 = json_object_new_int(7);
    json_object_object_add(uVar10,DAT_00114b20,uVar11);
    iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_00114b10);
    uVar11 = DAT_00114b24;
    if (iVar6 == 1) {
      uVar11 = DAT_00114b30;
    }
    uVar11 = json_object_new_string(uVar11);
    json_object_object_add(uVar10,DAT_00114b28,uVar11);
    uVar11 = json_object_to_json_string(uVar10);
    FCGI_printf(DAT_00114b2c,uVar11);
    json_object_put(uVar10);
    qcgisess_clear(iVar5);
  }
LAB_001145f0:
  post_authorized_call_hook(iVar3,iVar5);
  qcgisess_save(iVar5);
  (**(code **)(iVar5 + 0x58))(iVar5);
LAB_00114610:
  post_call_hook(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
  return;
}

