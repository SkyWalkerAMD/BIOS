
void FUN_00082154(void)

{
  if (DAT_000b8b18 == 0) {
    (**(code **)(DAT_000afbc8 + 0x170))(0x200,8,&LAB_000069ec,0,&DAT_000a56f0,&DAT_000b8b18);
  }
  DAT_000afd88 = 1;
  (**(code **)(DAT_000afbc8 + 0x68))(DAT_000b8b18);
  DAT_000afd88 = 0;
  return;
}

