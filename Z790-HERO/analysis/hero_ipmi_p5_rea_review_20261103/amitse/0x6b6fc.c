
void FUN_0006b6fc(longlong *param_1,longlong param_2)

{
  ushort uVar1;
  short sVar2;
  byte bVar3;
  char *pcVar4;
  
  uVar1 = *(ushort *)(param_2 + 0x14);
  if (uVar1 < 7) {
    if (uVar1 == 6) {
      *(undefined4 *)(param_1 + 1) = 0x6a;
      *(undefined4 *)((longlong)param_1 + 0xc) = 0xca;
      *(undefined4 *)(param_1 + 2) = 0x3f0;
      *(undefined2 *)(param_1 + 5) = 0x104;
      *(undefined4 *)((longlong)param_1 + 0x2c) = 0x1000a;
      FUN_0006b620(*param_1);
      return;
    }
    if (uVar1 != 1) {
      if (uVar1 == 2) {
        *(undefined4 *)(param_1 + 1) = 0x69;
        *(undefined4 *)((longlong)param_1 + 0xc) = 0xc9;
        *(undefined4 *)(param_1 + 2) = 0x3e9;
        *(undefined4 *)((longlong)param_1 + 0x2c) = 0x10001;
        return;
      }
      if (uVar1 != 3) {
        if (uVar1 == 4) {
          *(undefined4 *)(param_1 + 1) = 0x6c;
          *(undefined4 *)((longlong)param_1 + 0xc) = 0xc9;
          *(undefined4 *)(param_1 + 2) = 0x3f2;
          *(undefined4 *)((longlong)param_1 + 0x2c) = 0x1000f;
          return;
        }
        if (uVar1 != 5) {
          return;
        }
        *(undefined4 *)(param_1 + 1) = 0x6d;
        *(undefined4 *)((longlong)param_1 + 0xc) = 0xc9;
        *(undefined4 *)(param_1 + 2) = 0x3f3;
        *(undefined4 *)((longlong)param_1 + 0x2c) = 0x10010;
        return;
      }
      *(undefined4 *)(param_1 + 1) = 0x69;
      *(undefined4 *)(param_1 + 2) = 0x3e9;
      *(undefined4 *)((longlong)param_1 + 0x2c) = 0x10007;
LAB_0006b9bc:
      *(undefined4 *)((longlong)param_1 + 0xc) = 0;
      return;
    }
LAB_0006b7c3:
    *(undefined4 *)(param_1 + 1) = 0x69;
    *(undefined4 *)(param_1 + 2) = 0x3e9;
    *(undefined4 *)((longlong)param_1 + 0x2c) = 0x10002;
LAB_0006b7db:
    *(undefined4 *)((longlong)param_1 + 0xc) = 0xc9;
  }
  else {
    if (uVar1 == 10) {
      *(undefined4 *)(param_1 + 1) = 0x6b;
      *(undefined4 *)(param_1 + 2) = 0x3eb;
      *(undefined2 *)(param_1 + 5) = 0x104;
      *(undefined4 *)((longlong)param_1 + 0x2c) = 0x10004;
      goto LAB_0006b9bc;
    }
    if (uVar1 == 0xb) {
      pcVar4 = *(char **)(param_2 + 0x28);
      sVar2 = FUN_00026d98(pcVar4);
      bVar3 = 0x10;
      if ((*pcVar4 == '\a') && ((pcVar4[0xd] & 0x30U) != 0x20)) {
        bVar3 = (-((pcVar4[0xd] & 0x30U) != 0) & 0xeaU) + 0x20;
        if ((0x20 < bVar3) || ((0x100010400U >> ((ulonglong)bVar3 & 0x3f) & 1) == 0))
        goto LAB_0006b988;
      }
      if (sVar2 == 1) {
        if (bVar3 == 0x20) {
          *(undefined4 *)(param_1 + 1) = 0x6e;
          *(undefined4 *)((longlong)param_1 + 0xc) = 0xcc;
        }
        else {
          *(undefined4 *)(param_1 + 1) = 0x65;
          *(undefined4 *)((longlong)param_1 + 0xc) = 0xd0;
        }
      }
      else if (sVar2 == 2) {
        if (bVar3 == 0x20) {
          *(undefined4 *)(param_1 + 1) = 0x6f;
          *(undefined4 *)((longlong)param_1 + 0xc) = 0xcd;
        }
        else {
          *(undefined4 *)(param_1 + 1) = 0x66;
          *(undefined4 *)((longlong)param_1 + 0xc) = 0xd1;
        }
      }
      else if (sVar2 == 4) {
        if (bVar3 == 0x20) {
          *(undefined4 *)(param_1 + 1) = 0x70;
          *(undefined4 *)((longlong)param_1 + 0xc) = 0xce;
        }
        else {
          *(undefined4 *)(param_1 + 1) = 0x67;
          *(undefined4 *)((longlong)param_1 + 0xc) = 0xd2;
        }
      }
      else if (sVar2 == 8) {
        if (bVar3 == 0x20) {
          *(undefined4 *)(param_1 + 1) = 0x71;
          *(undefined4 *)((longlong)param_1 + 0xc) = 0xcf;
        }
        else {
          *(undefined4 *)(param_1 + 1) = 0x68;
          *(undefined4 *)((longlong)param_1 + 0xc) = 0xd3;
        }
      }
    }
    else {
      if (uVar1 == 0xd) {
        *(undefined4 *)(param_1 + 1) = 0x72;
        *(undefined4 *)(param_1 + 2) = 0x3ee;
        *(undefined4 *)((longlong)param_1 + 0x2c) = 0x1000c;
        goto LAB_0006b7db;
      }
      if (uVar1 != 0x13) {
        if (uVar1 != 0x1b) {
          return;
        }
        goto LAB_0006b7c3;
      }
      *(undefined4 *)(param_1 + 1) = 0x69;
      *(undefined4 *)((longlong)param_1 + 0xc) = 0xc9;
    }
LAB_0006b988:
    *(undefined4 *)(param_1 + 2) = 0x3ee;
    *(undefined4 *)((longlong)param_1 + 0x2c) = 0x10012;
  }
  *(undefined1 *)((longlong)param_1 + 0x29) = 1;
  return;
}

