
int __fastcall FUN_000002b9(int *param_1,int param_2,int *param_3)

{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *local_24;
  int local_20;
  undefined4 *local_1c;
  undefined4 *puStack_18;
  int *local_14;
  undefined1 local_10 [8];
  undefined1 auStack_8 [8];
  
  iVar4 = 0;
  local_24 = (int *)0x0;
  if ((param_2 == 0) || (param_3 == (int *)0x0)) {
    iVar3 = -0x7ffffffe;
  }
  else {
    local_1c = (undefined4 *)local_10;
    local_14 = param_1;
    while( true ) {
      uVar1 = InterruptDescriptorTableRegister();
      *local_1c = uVar1;
      iVar3 = (**(code **)(**(int **)(local_10._2_4_ + -4) + 0x38))
                        (*(int **)(local_10._2_4_ + -4),iVar4,&local_20);
      iVar5 = local_20;
      iVar4 = iVar4 + 1;
      if (iVar3 < 0) break;
      iVar3 = FUN_000004dc((int *)((uint)*(ushort *)(local_20 + 0x34) + local_20),(int *)0x740);
      if (iVar3 == 0) {
        local_24 = (int *)0x0;
        puStack_18 = (undefined4 *)auStack_8;
        while( true ) {
          uVar1 = InterruptDescriptorTableRegister();
          *puStack_18 = uVar1;
          iVar3 = (**(code **)(**(int **)(auStack_8._2_4_ + -4) + 0x3c))
                            (*(int **)(auStack_8._2_4_ + -4),2,iVar5,&local_24);
          piVar2 = local_24;
          if (iVar3 < 0) break;
          iVar3 = FUN_000004dc(local_24,local_14);
          iVar5 = local_20;
          if (iVar3 == 0) {
            local_14 = (int *)auStack_8;
            InterruptDescriptorTableRegister();
            iVar4 = (**(code **)(**(int **)(auStack_8._2_4_ + -4) + 0x40))
                              (*(int **)(auStack_8._2_4_ + -4),0x19,piVar2,param_2);
            if (iVar4 < 0) {
              return iVar4;
            }
            *param_3 = (local_24[5] & 0xffffffU) - 0x1c;
            return iVar4;
          }
        }
      }
    }
  }
  return iVar3;
}

