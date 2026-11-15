
undefined4 FUN_000138ec(int param_1,int param_2)

{
  int iVar1;
  
  if (param_2 < *(int *)(DAT_00013964 + 0x10)) {
    iVar1 = DAT_00013964 + param_2 * 4;
    IDBG_LINUXAPP_Runtime_DbgOut
              (0x87,DAT_00013974,DAT_00013970,DAT_0001396c,
               *(undefined4 *)(DAT_00013968 + *(int *)(iVar1 + 0x80) * 4),
               *(undefined4 *)(DAT_00013968 + param_1 * 4));
    *(int *)(iVar1 + 0x80) = param_1;
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013978,DAT_00013970,0x2b0);
  return 1;
}

