
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 Java_com_ami_iusb_HarddiskRedir_listHardDrives(longlong *param_1,undefined8 param_2)

{
  ulonglong uVar1;
  int iVar2;
  undefined8 uVar3;
  longlong *plVar4;
  undefined8 uVar5;
  ulonglong uVar6;
  int iVar7;
  ulonglong *puVar8;
  ulonglong *puVar9;
  undefined1 auStack_458 [32];
  ulonglong local_438 [128];
  ulonglong local_38;
  
                    /* 0x1150  6  Java_com_ami_iusb_HarddiskRedir_listHardDrives */
  local_38 = DAT_1800181d0 ^ (ulonglong)auStack_458;
  puVar8 = local_438;
  FUN_180004f80(local_438,0,0x400);
  uVar3 = (**(code **)(*param_1 + 0xf8))(param_1,param_2);
  uVar3 = (**(code **)(*param_1 + 0x2f0))(param_1,uVar3,"nativeReaderPointer",&DAT_18001234c);
  plVar4 = (longlong *)(**(code **)(*param_1 + 0x328))(param_1,param_2,uVar3);
  if ((longlong)plVar4 < 0) {
    printf("No reader!  Aborting...\n");
    uVar3 = 0;
  }
  else {
    iVar2 = (**(code **)(*plVar4 + 0x18))(plVar4,local_438,DAT_180018000);
    if (iVar2 < 1) {
      uVar3 = 0;
    }
    else {
      uVar3 = (**(code **)(*param_1 + 0x30))(param_1,"java/lang/String");
      uVar3 = (**(code **)(*param_1 + 0x560))(param_1,iVar2,uVar3,0);
      iVar7 = 0;
      if (0 < iVar2) {
        do {
          uVar5 = (**(code **)(*param_1 + 0x538))(param_1,puVar8);
          (**(code **)(*param_1 + 0x570))(param_1,uVar3,iVar7,uVar5);
          uVar6 = 0xffffffffffffffff;
          iVar7 = iVar7 + 1;
          puVar9 = puVar8;
          do {
            if (uVar6 == 0) break;
            uVar6 = uVar6 - 1;
            uVar1 = *puVar9;
            puVar9 = (ulonglong *)((longlong)puVar9 + 1);
          } while ((char)uVar1 != '\0');
          puVar8 = (ulonglong *)((longlong)puVar8 + ~uVar6);
        } while (iVar7 < iVar2);
      }
    }
  }
  return uVar3;
}

