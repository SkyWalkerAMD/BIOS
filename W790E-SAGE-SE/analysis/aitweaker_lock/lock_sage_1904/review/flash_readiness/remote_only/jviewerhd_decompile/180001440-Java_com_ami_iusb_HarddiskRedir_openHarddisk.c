
undefined4
Java_com_ami_iusb_HarddiskRedir_openHarddisk
          (longlong *param_1,undefined8 param_2,undefined8 param_3)

{
  int iVar1;
  undefined4 uVar2;
  void *_Memory;
  undefined8 uVar3;
  undefined8 *puVar4;
  
                    /* 0x1440  9  Java_com_ami_iusb_HarddiskRedir_openHarddisk */
  iVar1 = (**(code **)(*param_1 + 0x558))(param_1,param_3);
  _Memory = malloc((longlong)(iVar1 + 1));
  (**(code **)(*param_1 + 0x640))(param_1,param_3,0,iVar1,_Memory);
  *(undefined1 *)((longlong)iVar1 + (longlong)_Memory) = 0;
  uVar3 = (**(code **)(*param_1 + 0xf8))(param_1,param_2);
  uVar3 = (**(code **)(*param_1 + 0x2f0))(param_1,uVar3,"nativeReaderPointer",&DAT_18001234c);
  puVar4 = (undefined8 *)(**(code **)(*param_1 + 0x328))(param_1,param_2,uVar3);
  if ((longlong)puVar4 < 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = (**(code **)*puVar4)(puVar4,_Memory,0);
  }
  free(_Memory);
  return uVar2;
}

