
void FUN_000137a4(undefined4 param_1,undefined4 param_2,undefined1 param_3,int param_4)

{
  int iVar1;
  void *__s;
  
  __s = *(void **)(DAT_00013850 + param_4 * 4 + 0x10);
  memset(__s,0,0x6c);
  iVar1 = snprintf((char *)((int)__s + 0x3f),0x2d,DAT_00013854,param_2);
  if (0x2c < iVar1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00013864,DAT_00013860,DAT_0001385c);
  }
  memcpy(__s,DAT_00013858,8);
  *(char *)((int)__s + 0x17) = (char)param_4;
  *(undefined1 *)((int)__s + 0x3e) = param_3;
  *(undefined1 *)((int)__s + 0x29) = 0xf1;
  *(undefined1 *)((int)__s + 0xd) = 0;
  *(undefined1 *)((int)__s + 0xe) = 0;
  *(undefined1 *)((int)__s + 0xf) = 0;
  *(undefined1 *)((int)__s + 0xc) = 0x4c;
  FUN_00013494(param_1,param_4);
  return;
}

