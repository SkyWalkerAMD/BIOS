
void uploadBIOSFWImage_func(void)

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
  
  pcVar1 = getenv(DAT_00130064);
  iVar2 = qcgireq_setoption(0,1,DAT_00130068);
  if ((pcVar1 == (char *)0x0) || (uVar3 = strtoul(pcVar1,(char **)0x0,10), uVar3 == 0)) {
    FCGI_printf(DAT_001300a0);
    qcgires_setcontenttype(iVar2,DAT_00130084);
    uVar7 = json_object_new_object();
    uVar6 = 5;
LAB_0012ff70:
    uVar6 = json_object_new_int(uVar6);
    json_object_object_add(uVar7,DAT_00130088,uVar6);
    uVar6 = DAT_001300a4;
  }
  else {
    if (0x4300000 < uVar3) {
      FCGI_printf(DAT_001300a8);
      qcgires_setcontenttype(iVar2,DAT_00130084);
      uVar7 = json_object_new_object();
      uVar6 = 6;
      goto LAB_0012ff70;
    }
    if (iVar2 == 0) {
      qcgires_error(0,DAT_001300b0);
    }
    iVar2 = qcgireq_parse(iVar2,0);
    pre_call_hook();
    iVar4 = qcgisess_init(iVar2,0);
    if (iVar4 != 0) {
      pcVar1 = getenv(DAT_0013006c);
      iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00130070);
      if (iVar5 == 1 && pcVar1 != (char *)0x0) {
        __s1 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00130074,0);
        __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00130074,0);
        __n = strlen(__s);
        iVar5 = strncmp(__s1,pcVar1,__n);
        if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00130078), iVar5 != 0))
        goto LAB_0012fe88;
        pre_authorized_call_hook(iVar2,iVar4);
        uVar6 = json_object_new_object();
        pcVar1 = (char *)(**(code **)(iVar2 + 0x18))(iVar2,DAT_0013007c,0);
        iVar5 = rename(pcVar1,DAT_00130080);
        if (iVar5 == -1) {
          FCGI_fprintf(DAT_001300bc,DAT_001300b4,DAT_001300b8);
          qcgires_setcontenttype(iVar2,DAT_00130084);
LAB_00130058:
          FCGI_printf(DAT_001300c0);
        }
        else {
          qcgires_setcontenttype(iVar2,DAT_00130084);
          if (iVar5 != 0) goto LAB_00130058;
        }
        uVar7 = json_object_new_int(iVar5);
        json_object_object_add(uVar6,DAT_00130088,uVar7);
        uVar7 = json_object_to_json_string(uVar6);
        FCGI_printf(DAT_0013008c,uVar7);
        json_object_put(uVar6);
      }
      else {
LAB_0012fe88:
        FCGI_printf(DAT_00130090);
        FCGI_printf(DAT_00130094);
        qcgires_setcontenttype(iVar2,DAT_00130084);
        uVar7 = json_object_new_object();
        uVar6 = json_object_new_int(7);
        json_object_object_add(uVar7,DAT_00130088,uVar6);
        iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00130078);
        uVar6 = DAT_00130098;
        if (iVar5 == 1) {
          uVar6 = DAT_001300ac;
        }
        uVar6 = json_object_new_string(uVar6);
        json_object_object_add(uVar7,DAT_0013009c,uVar6);
        uVar6 = json_object_to_json_string(uVar7);
        FCGI_printf(DAT_0013008c,uVar6);
        json_object_put(uVar7);
        qcgisess_clear(iVar4);
      }
      post_authorized_call_hook(iVar2,iVar4);
      qcgisess_save(iVar4);
      (**(code **)(iVar4 + 0x58))(iVar4);
      goto LAB_0012ff38;
    }
    FCGI_printf(DAT_00130090);
    FCGI_printf(DAT_00130094);
    qcgires_setcontenttype(iVar2,DAT_00130084);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_00130088,uVar6);
    uVar6 = DAT_00130098;
  }
  uVar6 = json_object_new_string(uVar6);
  json_object_object_add(uVar7,DAT_0013009c,uVar6);
  uVar6 = json_object_to_json_string(uVar7);
  FCGI_printf(DAT_0013008c,uVar6);
  json_object_put(uVar7);
LAB_0012ff38:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x0012ff4c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

