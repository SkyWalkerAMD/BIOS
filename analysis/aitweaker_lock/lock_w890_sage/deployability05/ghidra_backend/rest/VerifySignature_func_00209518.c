
void VerifySignature_func(void)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  size_t sVar8;
  char *pcVar9;
  size_t sVar10;
  char *pcVar11;
  void *__ptr;
  int iVar12;
  undefined4 uVar13;
  int iVar14;
  undefined1 auStack_10038 [4];
  int iStack_10034;
  
  iVar1 = DAT_00209cbc;
  iVar14 = **(int **)(DAT_00209cb4 + 0x20952c + DAT_00209cb8);
  iVar2 = qcgireq_parse(0,0,0);
  pcVar3 = getenv((char *)(DAT_00209cc0 + 0x20956c));
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00209cc4 + 0x209598);
    FCGI_printf(DAT_00209cc8 + 0x2095a4);
    qcgires_setcontenttype(iVar2,DAT_00209ccc + 0x2095b4);
    iVar4 = json_object_new_object();
    uVar5 = json_object_new_int(7);
    json_object_object_add(iVar4,DAT_00209cd0 + 0x2095d8,uVar5);
    uVar5 = json_object_new_string(DAT_00209cd4 + 0x2095e4);
    json_object_object_add(iVar4,DAT_00209cd8 + 0x2095f8,uVar5);
    uVar5 = json_object_to_json_string(iVar4);
    FCGI_printf(DAT_00209cdc + 0x209610,uVar5);
    if (iVar4 != 0) {
      json_object_put(iVar4);
    }
    goto LAB_00209620;
  }
  iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00209ce4 + 0x20967c);
  if (pcVar3 == (char *)0x0 || iVar6 != 1) {
LAB_00209694:
    FCGI_printf(DAT_00209ce8 + 0x2096a0);
    FCGI_printf(DAT_00209cec + 0x2096ac);
    qcgires_setcontenttype(iVar2,DAT_00209cf0 + 0x2096bc);
    iVar6 = json_object_new_object();
    uVar5 = json_object_new_int(7);
    json_object_object_add(iVar6,DAT_00209cf4 + 0x2096e0,uVar5);
    iVar7 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00209cf8 + 0x2096f4);
    if (iVar7 == 1) {
      uVar5 = json_object_new_string(DAT_00209cfc + 0x209708);
      iVar7 = DAT_00209d00 + 0x209718;
    }
    else {
      iVar7 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00209d40 + 0x2099ac);
      if ((iVar7 == 1) &&
         (iVar7 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00209d44 + 0x2099c8), iVar7 == 0)) {
        uVar5 = json_object_new_string(DAT_00209d48 + 0x2099dc);
        iVar7 = DAT_00209d4c + 0x2099ec;
      }
      else {
        uVar5 = json_object_new_string(DAT_00209d50 + 0x2099f8);
        iVar7 = DAT_00209d54 + 0x209a08;
      }
    }
    json_object_object_add(iVar6,iVar7,uVar5);
    uVar5 = json_object_to_json_string(iVar6);
    FCGI_printf(DAT_00209d04 + 0x209734,uVar5);
    if (iVar6 != 0) {
      json_object_put(iVar6);
    }
    qcgisess_clear(iVar4);
  }
  else {
    sVar8 = strlen(pcVar3);
    iVar6 = DAT_00209d08 + 0x209790;
    pcVar9 = (char *)(**(code **)(iVar4 + 0x18))(iVar4);
    sVar10 = strlen(pcVar9);
    if (sVar8 != sVar10) goto LAB_00209694;
    pcVar9 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,iVar6,0);
    pcVar11 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,iVar6,0);
    sVar8 = strlen(pcVar11);
    iVar6 = strncmp(pcVar9,pcVar3,sVar8);
    if (((iVar6 != 0) ||
        (iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00209d0c + 0x2097fc), iVar6 != 0)) ||
       ((iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00209d10 + 0x209818), iVar6 == 1 &&
        (iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00209d14 + 0x209834), iVar6 == 0))))
    goto LAB_00209694;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar7 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar6 = json_object_new_object();
    pcVar3 = getenv((char *)(DAT_00209d18 + 0x209870));
    pcVar9 = getenv((char *)(DAT_00209d1c + 0x209880));
    if (pcVar3 == (char *)0x0) {
LAB_00209a1c:
      CMD_Verify_BIOS_Signature(auStack_10038);
      if (iStack_10034 == 0) {
        qcgires_setcontenttype(iVar2,DAT_00209d9c + 0x209c5c);
        uVar5 = json_object_to_json_string(iVar7);
        FCGI_printf(DAT_00209da0 + 0x209c74,uVar5);
        if (iVar7 != 0) {
          json_object_put(iVar7);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
      }
      else {
        if (iVar7 != 0) {
          json_object_put(iVar7);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        iVar7 = iVar6;
        if (pcVar3 != (char *)0x0) {
          iVar12 = strcasecmp(pcVar3,(char *)(DAT_00209d58 + 0x209a74));
          if ((iVar12 == 0 || pcVar9 == (char *)0x0) ||
             ((iVar12 = strcasecmp(pcVar3,(char *)(DAT_00209d5c + 0x209a98)), iVar12 == 0 &&
              (iVar12 = strncasecmp(pcVar9,(char *)(DAT_00209d60 + 0x209ab4),0x10), iVar12 == 0))))
          {
            if (iVar6 != 0) {
              json_object_put(iVar6);
              iVar7 = 0;
            }
          }
          else if (iVar6 != 0) {
            iVar7 = 0;
            json_object_put(iVar6);
          }
        }
        iVar12 = json_object_new_object();
        uVar5 = json_object_new_string_len(DAT_00209d80 + 0x209bc4,0x20);
        json_object_object_add(iVar12,DAT_00209d84 + 0x209bd8,uVar5);
        uVar5 = json_object_new_int(0x50e);
        json_object_object_add(iVar12,DAT_00209d88 + 0x209bf4,uVar5);
        FCGI_printf(DAT_00209d90 + 0x209c08,DAT_00209d8c + 0x209c04);
        qcgires_setcontenttype(iVar2,DAT_00209d94 + 0x209c18);
        uVar5 = json_object_to_json_string(iVar12);
        FCGI_printf(DAT_00209d98 + 0x209c30,uVar5);
        iVar6 = iVar7;
        if (iVar12 != 0) {
          json_object_put(iVar12);
        }
      }
      if (pcVar3 != (char *)0x0) {
LAB_00209b84:
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
      }
    }
    else {
      iVar12 = strcasecmp(pcVar3,(char *)(DAT_00209d20 + 0x20989c));
      if (__ptr == (void *)0x0 || iVar12 == 0) {
        iVar12 = strcasecmp(pcVar3,(char *)(DAT_00209d64 + 0x209ae4));
        if (__ptr != (void *)0x0 || iVar12 != 0) goto LAB_00209a1c;
        json_object_put(iVar6);
        FCGI_printf(DAT_00209d68 + 0x209b00);
        qcgires_setcontenttype(iVar2,DAT_00209d6c + 0x209b10);
        uVar5 = json_object_new_object();
        uVar13 = json_object_new_int(8);
        json_object_object_add(uVar5,DAT_00209d70 + 0x209b34,uVar13);
        uVar13 = json_object_new_string(DAT_00209d74 + 0x209b40);
        json_object_object_add(uVar5,DAT_00209d78 + 0x209b54,uVar13);
        uVar13 = json_object_to_json_string(uVar5);
        FCGI_printf(DAT_00209d7c + 0x209b6c,uVar13);
        json_object_put(uVar5);
        if (iVar7 != 0) {
          json_object_put(iVar7);
        }
        goto LAB_00209b84;
      }
      if (pcVar9 == (char *)0x0) goto LAB_00209a1c;
      iVar12 = strcasecmp(pcVar3,(char *)(DAT_00209d24 + 0x2098c0));
      if (iVar12 != 0) {
LAB_00209a08:
        json_object_put(iVar6);
        iVar6 = json_tokener_parse(__ptr);
        goto LAB_00209a1c;
      }
      pcVar11 = (char *)(DAT_00209d28 + 0x2098dc);
      iVar12 = strncasecmp(pcVar9,pcVar11,0x10);
      if (iVar12 != 0) goto LAB_00209a08;
      json_object_put(iVar6);
      iVar6 = json_tokener_parse(__ptr);
      if (iVar6 != 0) goto LAB_00209a1c;
      FCGI_printf(DAT_00209d2c + 0x20990c);
      qcgires_setcontenttype(iVar2,pcVar11);
      uVar5 = json_object_new_object();
      uVar13 = json_object_new_int(8);
      json_object_object_add(uVar5,DAT_00209d30 + 0x20993c,uVar13);
      uVar13 = json_object_new_string(DAT_00209d34 + 0x209948);
      json_object_object_add(uVar5,DAT_00209d38 + 0x20995c,uVar13);
      uVar13 = json_object_to_json_string(uVar5);
      FCGI_printf(DAT_00209d3c + 0x209974,uVar13);
      json_object_put(uVar5);
      if (iVar7 != 0) {
        json_object_put(iVar7);
      }
      free(__ptr);
    }
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_00209620:
  post_call_hook(iVar2);
  if (iVar2 != 0) {
    (**(code **)(iVar2 + 0x58))(iVar2);
  }
  if (iVar14 == **(int **)(DAT_00209ce0 + 0x209654 + DAT_00209cb8)) {
    FCGI_fflush(*(int *)(iVar1 + 0x209568 + DAT_00209da4) + 8,0,0);
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

