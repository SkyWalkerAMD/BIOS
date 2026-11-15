
void FUN_00014090(undefined4 param_1,char *param_2,undefined1 param_3,int param_4)

{
  void *__s;
  
  __s = *(void **)(DAT_00014118 + param_4 * 4 + 0x10);
  memset(__s,0,0x6c);
  strncpy((char *)((int)__s + 0x3f),param_2,0x2c);
  memcpy(__s,DAT_0001411c,8);
  *(undefined1 *)((int)__s + 0x3e) = param_3;
  *(char *)((int)__s + 0x17) = (char)param_4;
  *(undefined1 *)((int)__s + 0x29) = 0xf1;
  *(undefined1 *)((int)__s + 0xc) = 0x4c;
  *(undefined1 *)((int)__s + 0xd) = 0;
  *(undefined1 *)((int)__s + 0xe) = 0;
  *(undefined1 *)((int)__s + 0xf) = 0;
  FUN_00013c74(param_1,param_4);
  return;
}

