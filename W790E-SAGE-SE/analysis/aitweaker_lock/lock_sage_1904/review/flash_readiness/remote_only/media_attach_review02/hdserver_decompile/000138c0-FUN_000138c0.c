
undefined4 FUN_000138c0(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = DAT_00013944;
  iVar2 = DAT_00013944 + param_2 * 4;
  IDBG_LINUXAPP_Runtime_DbgOut
            (0x87,DAT_00013954,DAT_00013950,DAT_0001394c,
             *(undefined4 *)(DAT_00013948 + *(int *)(iVar2 + 0x144) * 4 + 0x10),
             *(undefined4 *)(DAT_00013948 + param_1 * 4 + 0x10));
  if (*(int *)(iVar1 + 0x130) <= param_2) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001395c,DAT_00013950,DAT_00013958);
    return 1;
  }
  *(int *)(iVar2 + 0x144) = param_1;
  return 0;
}

