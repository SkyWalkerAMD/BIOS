
void uploadHPMBIOSFWImage_func(void)

{
  char *pcVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  char *__s1;
  char *__s;
  size_t __n;
  undefined4 uVar5;
  undefined4 uVar6;
  ulonglong uVar7;
  
  pcVar1 = getenv(DAT_000f1910);
  iVar2 = qcgireq_setoption(0,1,DAT_000f1914);
  if (pcVar1 != (char *)0x0) {
    uVar7 = strtoull(pcVar1,(char **)0x0,10);
    if (uVar7 != 0) {
      if (((int)(uVar7 >> 0x20) != 0 || 0x45fffff < (uint)uVar7) && uVar7 != 0x4600000) {
        FCGI_printf(DAT_000f1958);
        qcgires_setcontenttype(iVar2,DAT_000f1934);
        uVar6 = json_object_new_object();
        uVar5 = 6;
        goto LAB_000f16e8;
      }
      if (iVar2 == 0) {
        qcgires_error(0,DAT_000f196c);
      }
      iVar2 = qcgireq_parse(iVar2,0);
      if (iVar2 == 0) {
        FCGI_printf(DAT_000f1960);
        qcgires_setcontenttype(0,DAT_000f1934);
        uVar5 = json_object_new_object();
        uVar6 = json_object_new_int(7);
        json_object_object_add(uVar5,DAT_000f1964,uVar6);
        uVar6 = json_object_new_string(DAT_000f1968);
        json_object_object_add(uVar5,DAT_000f194c,uVar6);
        uVar6 = json_object_to_json_string(uVar5);
        FCGI_printf(DAT_000f193c,uVar6);
        json_object_put(uVar5);
        post_call_hook(0);
        return;
      }
      pre_call_hook();
      iVar3 = qcgisess_init(iVar2,0);
      if (iVar3 == 0) {
        FCGI_printf(DAT_000f1940);
        FCGI_printf(DAT_000f1944);
        qcgires_setcontenttype(iVar2,DAT_000f1934);
        uVar5 = json_object_new_object();
        uVar6 = json_object_new_int(7);
        json_object_object_add(uVar5,DAT_000f1938,uVar6);
        uVar6 = json_object_new_string(DAT_000f1948);
        json_object_object_add(uVar5,DAT_000f194c,uVar6);
        uVar6 = json_object_to_json_string(uVar5);
        FCGI_printf(DAT_000f193c,uVar6);
        json_object_put(uVar5);
        goto LAB_000f16b0;
      }
      pcVar1 = getenv(DAT_000f1918);
      iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000f191c);
      if (iVar4 == 1 && pcVar1 != (char *)0x0) {
        __s1 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000f1920,0);
        __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000f1920,0);
        __n = strlen(__s);
        iVar4 = strncmp(__s1,pcVar1,__n);
        if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000f1924), iVar4 != 0))
        goto LAB_000f1600;
        pre_authorized_call_hook(iVar2,iVar3);
        iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000f1928);
        if (iVar4 < 4) {
          qcgires_setcontenttype(iVar2,DAT_000f1934);
          uVar5 = json_object_new_object();
          uVar6 = json_object_new_int(8000);
          json_object_object_add(uVar5,DAT_000f1964,uVar6);
          uVar6 = json_object_new_string_len(DAT_000f1970,0x16);
          json_object_object_add(uVar5,DAT_000f194c,uVar6);
          FCGI_printf(DAT_000f1978,DAT_000f1974);
          uVar6 = json_object_to_json_string(uVar5);
          FCGI_printf(DAT_000f193c,uVar6);
          json_object_put(uVar5);
        }
        else {
          uVar5 = json_object_new_object();
          pcVar1 = (char *)(**(code **)(iVar2 + 0x18))(iVar2,DAT_000f192c,0);
          iVar4 = rename(pcVar1,DAT_000f1930);
          if (iVar4 == -1) {
            FCGI_fprintf(DAT_000f1984,DAT_000f197c,DAT_000f1980);
            qcgires_setcontenttype(iVar2,DAT_000f1934);
LAB_000f1904:
            FCGI_printf(DAT_000f1988);
          }
          else {
            qcgires_setcontenttype(iVar2,DAT_000f1934);
            if (iVar4 != 0) goto LAB_000f1904;
          }
          uVar6 = json_object_new_int(iVar4);
          json_object_object_add(uVar5,DAT_000f1938,uVar6);
          uVar6 = json_object_to_json_string(uVar5);
          FCGI_printf(DAT_000f193c,uVar6);
          json_object_put(uVar5);
        }
      }
      else {
LAB_000f1600:
        FCGI_printf(DAT_000f1940);
        FCGI_printf(DAT_000f1944);
        qcgires_setcontenttype(iVar2,DAT_000f1934);
        uVar6 = json_object_new_object();
        uVar5 = json_object_new_int(7);
        json_object_object_add(uVar6,DAT_000f1938,uVar5);
        iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000f1924);
        uVar5 = DAT_000f1948;
        if (iVar4 == 1) {
          uVar5 = DAT_000f195c;
        }
        uVar5 = json_object_new_string(uVar5);
        json_object_object_add(uVar6,DAT_000f194c,uVar5);
        uVar5 = json_object_to_json_string(uVar6);
        FCGI_printf(DAT_000f193c,uVar5);
        json_object_put(uVar6);
        qcgisess_clear(iVar3);
      }
      post_authorized_call_hook(iVar2,iVar3);
      qcgisess_save(iVar3);
      (**(code **)(iVar3 + 0x58))(iVar3);
LAB_000f16b0:
      post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x000f16c4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      (**(code **)(iVar2 + 0x58))(iVar2);
      return;
    }
  }
  FCGI_printf(DAT_000f1950);
  qcgires_setcontenttype(iVar2,DAT_000f1934);
  uVar6 = json_object_new_object();
  uVar5 = 5;
LAB_000f16e8:
  uVar5 = json_object_new_int(uVar5);
  json_object_object_add(uVar6,DAT_000f1938,uVar5);
  uVar5 = json_object_new_string(DAT_000f1954);
  json_object_object_add(uVar6,DAT_000f194c,uVar5);
  uVar5 = json_object_to_json_string(uVar6);
  FCGI_printf(DAT_000f193c,uVar5);
  json_object_put(uVar6);
  post_call_hook(iVar2);
  if (iVar2 != 0) {
                    /* WARNING: Could not recover jumptable at 0x000f174c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(iVar2 + 0x58))(iVar2);
    return;
  }
  return;
}

