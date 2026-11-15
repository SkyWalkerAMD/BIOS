
void Java_com_ami_iusb_HarddiskRedir_closeHarddisk(longlong *param_1,undefined8 param_2)

{
  undefined8 uVar1;
  longlong *plVar2;
  
                    /* 0x1530  2  Java_com_ami_iusb_HarddiskRedir_closeHarddisk */
  uVar1 = (**(code **)(*param_1 + 0xf8))();
  uVar1 = (**(code **)(*param_1 + 0x2f0))(param_1,uVar1,"nativeReaderPointer",&DAT_18001234c);
  plVar2 = (longlong *)(**(code **)(*param_1 + 0x328))(param_1,param_2,uVar1);
  if (-1 < (longlong)plVar2) {
    (**(code **)(*plVar2 + 8))(plVar2);
  }
  return;
}

