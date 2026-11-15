
void FUN_00018a80(undefined8 *param_1,int param_2,short *param_3,undefined8 *param_4,char *param_5,
                 ulonglong *param_6,longlong *param_7,ulonglong *param_8,undefined4 *param_9)

{
  char cVar1;
  ulonglong uVar2;
  
  uVar2 = 0;
  if (param_5 != (char *)0x0) {
    cVar1 = *param_5;
    while (cVar1 != '\0') {
      uVar2 = uVar2 + 1;
      cVar1 = param_5[uVar2];
    }
  }
  FUN_00018af0(param_1,param_2,param_3,param_4,(longlong)param_5,uVar2,param_6,param_7,param_8,
               param_9);
  return;
}

