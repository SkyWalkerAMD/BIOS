
void Java_com_ami_iusb_HarddiskRedir_newHarddiskReader
               (longlong *param_1,undefined8 param_2,char param_3)

{
  undefined8 uVar1;
  void *_Memory;
  undefined8 *puVar2;
  
                    /* 0x12c0  8  Java_com_ami_iusb_HarddiskRedir_newHarddiskReader */
  uVar1 = (**(code **)(*param_1 + 0xf8))();
  uVar1 = (**(code **)(*param_1 + 0x2f0))(param_1,uVar1,"nativeReaderPointer",&DAT_18001234c);
  _Memory = (void *)(**(code **)(*param_1 + 0x328))(param_1);
  if (0 < (longlong)_Memory) {
    free(_Memory);
  }
  if (param_3 == '\0') {
    puVar2 = (undefined8 *)FUN_18000506c(0x140);
    if (puVar2 != (undefined8 *)0x0) {
      puVar2 = FUN_180001a60(puVar2,0,0);
      goto LAB_18000136d;
    }
  }
  else {
    puVar2 = (undefined8 *)FUN_18000506c(0xf8);
    if (puVar2 != (undefined8 *)0x0) {
      puVar2 = FUN_1800030e0(puVar2);
      goto LAB_18000136d;
    }
  }
  puVar2 = (undefined8 *)0x0;
LAB_18000136d:
                    /* WARNING: Could not recover jumptable at 0x00018000138d. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(*param_1 + 0x370))(param_1,param_2,uVar1,puVar2);
  return;
}

