
void uploadHPMBIOSFWImage_func(void)

{
  char *pcVar1;
  int iVar2;
  ulong uVar3;
  int iVar4;
  int iVar5;
  char *__s1;
  char *__s;
  size_t __n;
  undefined4 uVar6;
  undefined4 uVar7;
  
  pcVar1 = getenv(DAT_000ed1a8);
  iVar2 = qcgireq_setoption(0,1,DAT_000ed1ac);
  if ((pcVar1 == (char *)0x0) || (uVar3 = strtoul(pcVar1,(char **)0x0,10), uVar3 == 0)) {
    FCGI_printf(DAT_000ed1e4);
    qcgires_setcontenttype(iVar2,DAT_000ed1c8);
    uVar7 = json_object_new_object();
    uVar6 = 5;
LAB_000ed0b4:
    uVar6 = json_object_new_int(uVar6);
    json_object_object_add(uVar7,DAT_000ed1cc,uVar6);
    uVar6 = DAT_000ed1e8;
  }
  else {
    if (0x4600000 < uVar3) {
      FCGI_printf(DAT_000ed1ec);
      qcgires_setcontenttype(iVar2,DAT_000ed1c8);
      uVar7 = json_object_new_object();
      uVar6 = 6;
      goto LAB_000ed0b4;
    }
    if (iVar2 == 0) {
      qcgires_error(0,DAT_000ed1f4);
    }
    iVar2 = qcgireq_parse(iVar2,0);
    pre_call_hook();
    iVar4 = qcgisess_init(iVar2,0);
    if (iVar4 != 0) {
      pcVar1 = getenv(DAT_000ed1b0);
      iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000ed1b4);
      if (iVar5 == 1 && pcVar1 != (char *)0x0) {
        __s1 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000ed1b8,0);
        __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000ed1b8,0);
        __n = strlen(__s);
        iVar5 = strncmp(__s1,pcVar1,__n);
        if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000ed1bc), iVar5 != 0))
        goto LAB_000ecfcc;
        pre_authorized_call_hook(iVar2,iVar4);
        uVar6 = json_object_new_object();
        pcVar1 = (char *)(**(code **)(iVar2 + 0x18))(iVar2,DAT_000ed1c0,0);
        iVar5 = rename(pcVar1,DAT_000ed1c4);
        if (iVar5 == -1) {
          FCGI_fprintf(DAT_000ed200,DAT_000ed1f8,DAT_000ed1fc);
          qcgires_setcontenttype(iVar2,DAT_000ed1c8);
LAB_000ed19c:
          FCGI_printf(DAT_000ed204);
        }
        else {
          qcgires_setcontenttype(iVar2,DAT_000ed1c8);
          if (iVar5 != 0) goto LAB_000ed19c;
        }
        uVar7 = json_object_new_int(iVar5);
        json_object_object_add(uVar6,DAT_000ed1cc,uVar7);
        uVar7 = json_object_to_json_string(uVar6);
        FCGI_printf(DAT_000ed1d0,uVar7);
        json_object_put(uVar6);
      }
      else {
LAB_000ecfcc:
        FCGI_printf(DAT_000ed1d4);
        FCGI_printf(DAT_000ed1d8);
        qcgires_setcontenttype(iVar2,DAT_000ed1c8);
        uVar7 = json_object_new_object();
        uVar6 = json_object_new_int(7);
        json_object_object_add(uVar7,DAT_000ed1cc,uVar6);
        iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000ed1bc);
        uVar6 = DAT_000ed1dc;
        if (iVar5 == 1) {
          uVar6 = DAT_000ed1f0;
        }
        uVar6 = json_object_new_string(uVar6);
        json_object_object_add(uVar7,DAT_000ed1e0,uVar6);
        uVar6 = json_object_to_json_string(uVar7);
        FCGI_printf(DAT_000ed1d0,uVar6);
        json_object_put(uVar7);
        qcgisess_clear(iVar4);
      }
      post_authorized_call_hook(iVar2,iVar4);
      qcgisess_save(iVar4);
      (**(code **)(iVar4 + 0x58))(iVar4);
      goto LAB_000ed07c;
    }
    FCGI_printf(DAT_000ed1d4);
    FCGI_printf(DAT_000ed1d8);
    qcgires_setcontenttype(iVar2,DAT_000ed1c8);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_000ed1cc,uVar6);
    uVar6 = DAT_000ed1dc;
  }
  uVar6 = json_object_new_string(uVar6);
  json_object_object_add(uVar7,DAT_000ed1e0,uVar6);
  uVar6 = json_object_to_json_string(uVar7);
  FCGI_printf(DAT_000ed1d0,uVar6);
  json_object_put(uVar7);
LAB_000ed07c:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x000ed090. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

