
void Java_com_ami_iusb_HarddiskRedir_deleteHarddiskReader(longlong *param_1,undefined8 param_2)

{
  undefined8 uVar1;
  longlong *_Memory;
  
                    /* 0x13a0  3  Java_com_ami_iusb_HarddiskRedir_deleteHarddiskReader */
  uVar1 = (**(code **)(*param_1 + 0xf8))();
  uVar1 = (**(code **)(*param_1 + 0x2f0))(param_1,uVar1,"nativeReaderPointer",&DAT_18001234c);
  _Memory = (longlong *)(**(code **)(*param_1 + 0x328))(param_1,param_2,uVar1);
  if (-1 < (longlong)_Memory) {
    (**(code **)(*_Memory + 8))(_Memory);
    free(_Memory);
    (**(code **)(*param_1 + 0x370))(param_1,param_2,uVar1,0xffffffffffffffff);
  }
  return;
}

