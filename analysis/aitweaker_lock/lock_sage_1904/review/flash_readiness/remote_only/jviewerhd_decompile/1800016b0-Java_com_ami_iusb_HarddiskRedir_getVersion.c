
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 Java_com_ami_iusb_HarddiskRedir_getVersion(longlong *param_1,undefined8 param_2)

{
  undefined8 uVar1;
  longlong *plVar2;
  undefined8 *puVar3;
  undefined1 auStack_58 [32];
  void *local_38 [3];
  ulonglong local_20;
  ulonglong local_10;
  
                    /* 0x16b0  5  Java_com_ami_iusb_HarddiskRedir_getVersion */
  local_10 = DAT_1800181d0 ^ (ulonglong)auStack_58;
  uVar1 = (**(code **)(*param_1 + 0xf8))();
  uVar1 = (**(code **)(*param_1 + 0x2f0))(param_1,uVar1,"nativeReaderPointer",&DAT_18001234c);
  plVar2 = (longlong *)(**(code **)(*param_1 + 0x328))(param_1,param_2,uVar1);
  if ((longlong)plVar2 < 0) {
    printf("No reader!  Aborting...\n");
    uVar1 = 0;
  }
  else {
    puVar3 = (undefined8 *)(**(code **)(*plVar2 + 0x30))(plVar2,local_38);
    if (0xf < (ulonglong)puVar3[3]) {
      puVar3 = (undefined8 *)*puVar3;
    }
    uVar1 = (**(code **)(*param_1 + 0x538))(param_1,puVar3);
    if (0xf < local_20) {
      free(local_38[0]);
    }
  }
  return uVar1;
}

