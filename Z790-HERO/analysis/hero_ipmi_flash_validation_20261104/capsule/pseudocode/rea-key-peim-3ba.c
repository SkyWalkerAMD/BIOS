
int __fastcall FUN_000003ba(int *param_1,int *param_2)

{
  undefined4 *puVar1;
  int iVar2;
  int *piVar3;
  byte bVar4;
  int local_c;
  uint local_8;
  undefined4 *local_4;
  
  if (param_2 == (int *)0x0) {
    iVar2 = -0x7ffffffe;
  }
  else if (*param_2 == 0) {
    bVar4 = 0;
    iVar2 = -0x7ffffff2;
    if (DAT_00000750 != 0) {
      piVar3 = &DAT_00000750;
      do {
        iVar2 = FUN_000002b9((int *)*piVar3,(int)&local_4,(int *)&local_8);
        if (-1 < iVar2) {
          iVar2 = (**(code **)(*param_1 + 0x34))(param_1,4,local_8 + 0x34,&local_c);
          if (iVar2 < 0) {
            return iVar2;
          }
          *(undefined4 *)(local_c + 8) = DAT_00000720;
          *(undefined4 *)(local_c + 0xc) = DAT_00000724;
          *(undefined4 *)(local_c + 0x10) = DAT_00000728;
          *(undefined4 *)(local_c + 0x14) = DAT_0000072c;
          puVar1 = *(undefined4 **)((uint)bVar4 * 4 + 0x760);
          *(undefined4 *)(local_c + 0x18) = *puVar1;
          *(undefined4 *)(local_c + 0x1c) = puVar1[1];
          *(undefined4 *)(local_c + 0x20) = puVar1[2];
          *(undefined4 *)(local_c + 0x24) = puVar1[3];
          *(uint *)(local_c + 0x30) = local_8;
          *(undefined4 **)(local_c + 0x28) = local_4;
          *(undefined4 *)(local_c + 0x2c) = 0;
          FUN_000005a0((undefined4 *)(local_c + 0x34),local_4,local_8);
          *param_2 = local_c;
          (**(code **)(*param_1 + 0x18))(param_1,0x770);
          return iVar2;
        }
        bVar4 = bVar4 + 1;
        piVar3 = (int *)((uint)bVar4 * 4 + 0x750);
      } while (*piVar3 != 0);
    }
  }
  else {
    iVar2 = 0;
  }
  return iVar2;
}

