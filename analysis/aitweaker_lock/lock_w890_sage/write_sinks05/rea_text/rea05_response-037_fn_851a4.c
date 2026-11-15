
ulonglong WS05_851a4(uint *param_1,ulonglong param_2)

{
  undefined8 uVar1;
  undefined *puVar2;
  word *pwVar3;
  
  DAT_000b8b80 = 0;
  DAT_000afd88 = 1;
  FUN_0008221c(param_1,param_2);
  DAT_000afd88 = 0;
  FUN_0000fd6c(0xffff001d,&LAB_0004f458,DAT_000afce8,0);
  pwVar3 = &IMAGE_DOS_HEADER_00000000.e_cblp;
  puVar2 = &DAT_00093288;
  (**(code **)(DAT_000afbd8 + 0x58))();
  uVar1 = FUN_0001fcb4(0,puVar2,pwVar3);
  (**(code **)(DAT_000afbd8 + 0x58))(u_RfSbPhysicalUserPresent_000acc60,&DAT_00093288,0,0,0);
  return -(ulonglong)((char)uVar1 != '\x01') & 0x8000000000000015;
}

