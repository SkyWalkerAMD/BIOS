
int Java_com_ami_iusb_HarddiskRedir_executeHarddiskSCSICmd
              (longlong *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 uVar1;
  longlong *plVar2;
  undefined8 uVar3;
  int local_res8 [2];
  
                    /* 0x15a0  4  Java_com_ami_iusb_HarddiskRedir_executeHarddiskSCSICmd */
  uVar1 = (**(code **)(*param_1 + 0xf8))();
  uVar1 = (**(code **)(*param_1 + 0x2f0))(param_1,uVar1,"nativeReaderPointer",&DAT_18001234c);
  plVar2 = (longlong *)(**(code **)(*param_1 + 0x328))(param_1,param_2,uVar1);
  if ((longlong)plVar2 < 0) {
    printf("No reader!  Aborting...\n");
    local_res8[0] = -1;
  }
  else {
    uVar1 = (**(code **)(*param_1 + 0x730))(param_1,param_3);
    uVar3 = (**(code **)(*param_1 + 0x730))(param_1,param_4);
    (**(code **)(*plVar2 + 0x10))(plVar2,uVar1,uVar3,local_res8);
    local_res8[0] = local_res8[0] + 0x3d;
  }
  return local_res8[0];
}

