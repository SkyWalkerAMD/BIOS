
void modifyoob_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *__s;
  size_t __n;
  undefined4 uVar7;
  undefined4 uVar8;
  void *__ptr;
  int iVar9;
  int iVar10;
  char acStack_74 [32];
  undefined1 auStack_54 [48];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_001378f4);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00137904);
    FCGI_printf(DAT_00137908);
    qcgires_setcontenttype(iVar2,DAT_0013790c);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_00137910,uVar7);
    uVar7 = json_object_new_string(DAT_00137914);
    json_object_object_add(uVar8,DAT_00137918,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0013791c,uVar7);
    json_object_put(uVar8);
    goto LAB_00137134;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_001378f8);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_001378fc,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_001378fc,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00137900), iVar5 != 0))
    goto LAB_00137084;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(2);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_00137924);
    pcVar6 = getenv(DAT_00137928);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_0013792c),
       iVar10 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    if (*DAT_00137930 == 0) {
LAB_0013722c:
      memset(acStack_74,0,0x20);
      json_object_object_get_rest(iVar9,DAT_0013793c);
      uVar8 = json_object_get_string();
      iVar10 = safe_system(DAT_00137940);
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00137944,iVar10);
      if (iVar10 == 0) {
        iVar10 = safe_system(DAT_00137948);
        IDBG_LINUXAPP_DbgOut(0x86,DAT_0013794c,iVar10);
        if (iVar10 == 0) {
          iVar10 = safe_system(DAT_00137950);
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00137954,iVar10);
          if (iVar10 == 0) {
            snprintf(acStack_74,0x20,DAT_00137958,uVar8);
            iVar10 = safe_system(acStack_74);
            IDBG_LINUXAPP_DbgOut(0x86,DAT_0013795c,iVar10);
            if (iVar10 == 0) {
              iVar10 = safe_system(DAT_00137960);
              IDBG_LINUXAPP_DbgOut(0x86,DAT_00137964,iVar10);
              if (iVar10 == 0) {
                safe_system(DAT_00137968);
                qcgires_setcontenttype(iVar2,DAT_0013790c);
                uVar8 = json_object_to_json_string(iVar5);
                FCGI_printf(DAT_0013791c,uVar8);
                IPMI_lo_Logout(auStack_54);
                if (iVar5 != 0) {
                  json_object_put(iVar5);
                }
                if (__ptr != (void *)0x0) {
                  free(__ptr);
                }
                if (pcVar3 != (char *)0x0) {
                  strcasecmp(pcVar3,DAT_0013792c);
                  goto LAB_00137404;
                }
                goto LAB_00137114;
              }
              safe_system(DAT_00137968);
              IPMI_lo_Logout(auStack_54);
              if (iVar5 != 0) {
                json_object_put(iVar5);
              }
              if (__ptr != (void *)0x0) {
                free(__ptr);
              }
              if (pcVar3 != (char *)0x0) {
                strcasecmp(pcVar3,DAT_0013792c);
                if (iVar9 != 0) {
                  json_object_put(iVar9);
                }
                iVar5 = json_object_new_object();
                uVar8 = json_object_new_string_len(DAT_0013796c,0x19);
                json_object_object_add(iVar5,DAT_00137918,uVar8);
                uVar8 = DAT_00137970;
                goto LAB_001373a8;
              }
              iVar5 = json_object_new_object();
              uVar8 = json_object_new_string_len(DAT_0013796c,0x19);
              json_object_object_add(iVar5,DAT_00137918,uVar8);
              uVar8 = DAT_00137970;
            }
            else {
              safe_system(DAT_00137960);
              safe_system(DAT_00137968);
              IPMI_lo_Logout(auStack_54);
              if (iVar5 != 0) {
                json_object_put(iVar5);
              }
              if (__ptr != (void *)0x0) {
                free(__ptr);
              }
              if (pcVar3 != (char *)0x0) {
                strcasecmp(pcVar3,DAT_0013792c);
                if (iVar9 != 0) {
                  json_object_put(iVar9);
                }
                iVar5 = json_object_new_object();
                uVar8 = json_object_new_string_len(DAT_001379a4,0x16);
                json_object_object_add(iVar5,DAT_00137918,uVar8);
                uVar8 = DAT_001379a8;
                goto LAB_001373a8;
              }
              iVar5 = json_object_new_object();
              uVar8 = json_object_new_string_len(DAT_001379a4,0x16);
              json_object_object_add(iVar5,DAT_00137918,uVar8);
              uVar8 = DAT_001379a8;
            }
          }
          else {
            IPMI_lo_Logout(auStack_54);
            if (iVar5 != 0) {
              json_object_put(iVar5);
            }
            if (__ptr != (void *)0x0) {
              free(__ptr);
            }
            if (pcVar3 != (char *)0x0) {
              strcasecmp(pcVar3,DAT_0013792c);
              if (iVar9 != 0) {
                json_object_put(iVar9);
              }
              iVar5 = json_object_new_object();
              uVar8 = json_object_new_string_len(DAT_00137980,0x1b);
              json_object_object_add(iVar5,DAT_00137918,uVar8);
              uVar8 = DAT_00137984;
              goto LAB_001373a8;
            }
            iVar5 = json_object_new_object();
            uVar8 = json_object_new_string_len(DAT_00137980,0x1b);
            json_object_object_add(iVar5,DAT_00137918,uVar8);
            uVar8 = DAT_00137984;
          }
        }
        else {
          IPMI_lo_Logout(auStack_54);
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 != (char *)0x0) {
            strcasecmp(pcVar3,DAT_0013792c);
            if (iVar9 != 0) {
              json_object_put(iVar9);
            }
            iVar5 = json_object_new_object();
            uVar8 = json_object_new_string_len(DAT_00137990,0x1c);
            json_object_object_add(iVar5,DAT_00137918,uVar8);
            uVar8 = DAT_00137994;
            goto LAB_001373a8;
          }
          iVar5 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_00137990,0x1c);
          json_object_object_add(iVar5,DAT_00137918,uVar8);
          uVar8 = DAT_00137994;
        }
      }
      else {
        IPMI_lo_Logout(auStack_54);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 != (char *)0x0) {
          strcasecmp(pcVar3,DAT_0013792c);
          if (iVar9 != 0) {
            json_object_put(iVar9);
          }
          iVar5 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_00137988,0x3f);
          json_object_object_add(iVar5,DAT_00137918,uVar8);
          uVar8 = DAT_0013798c;
LAB_001373a8:
          uVar8 = json_object_new_int(uVar8);
          json_object_object_add(iVar5,DAT_00137974,uVar8);
          uVar8 = DAT_00137978;
          goto LAB_001373c0;
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_00137988,0x3f);
        json_object_object_add(iVar5,DAT_00137918,uVar8);
        uVar8 = DAT_0013798c;
      }
      uVar8 = json_object_new_int(uVar8);
      json_object_object_add(iVar5,DAT_00137974,uVar8);
      uVar8 = DAT_00137978;
LAB_001376dc:
      FCGI_printf(DAT_0013797c,uVar8);
      qcgires_setcontenttype(iVar2,DAT_0013790c);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0013791c,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00137934);
      iVar10 = IPMI_lo_Login(DAT_00137938,DAT_00137938,auStack_54,uVar1,1,0,0,0);
      if (iVar10 == 0) goto LAB_0013722c;
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_00137998,0x20);
        json_object_object_add(iVar5,DAT_00137918,uVar8);
        uVar8 = json_object_new_int(DAT_0013799c);
        json_object_object_add(iVar5,DAT_00137974,uVar8);
        uVar8 = DAT_001379a0;
        goto LAB_001376dc;
      }
      strcasecmp(pcVar3,DAT_0013792c);
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
      iVar5 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_00137998,0x20);
      json_object_object_add(iVar5,DAT_00137918,uVar8);
      uVar8 = json_object_new_int(DAT_0013799c);
      json_object_object_add(iVar5,DAT_00137974,uVar8);
      uVar8 = DAT_001379a0;
LAB_001373c0:
      FCGI_printf(DAT_0013797c,uVar8);
      qcgires_setcontenttype(iVar2,DAT_0013790c);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0013791c,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      strcasecmp(pcVar3,DAT_0013792c);
LAB_00137404:
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
  }
  else {
LAB_00137084:
    FCGI_printf(DAT_00137904);
    FCGI_printf(DAT_00137908);
    qcgires_setcontenttype(iVar2,DAT_0013790c);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_00137910,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00137900);
    uVar8 = DAT_00137914;
    if (iVar5 == 1) {
      uVar8 = DAT_00137920;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_00137918,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0013791c,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
LAB_00137114:
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_00137134:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

