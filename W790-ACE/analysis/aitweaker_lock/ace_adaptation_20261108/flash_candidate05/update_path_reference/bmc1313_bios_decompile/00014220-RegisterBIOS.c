
void RegisterBIOS(int param_1)

{
  undefined4 uVar1;
  
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00014260,DAT_0001425c,DAT_00014258);
  uVar1 = DAT_00014268;
  *(undefined4 *)(param_1 + 0x10c) = DAT_00014264;
  *(undefined4 *)(param_1 + 0x104) = uVar1;
  *(undefined4 *)(param_1 + 0x110) = 0;
  return;
}

