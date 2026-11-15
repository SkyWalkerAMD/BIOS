
void WS05_576e4(void)

{
  longlong lVar1;
  int local_res8 [2];
  undefined8 local_res10 [3];
  
  local_res8[0] = 0;
  local_res10[0] = 4;
  lVar1 = (**(code **)(DAT_000afbd8 + 0x48))
                    (u_AmiHardwareSignatureSetupUpdateC_000aa7c0,&DAT_00095568,0,local_res10,
                     local_res8);
  if (lVar1 < 0) {
    (**(code **)(DAT_000afbc8 + 0x168))(local_res8,4,0);
  }
  local_res8[0] = local_res8[0] + 1;
  (**(code **)(DAT_000afbd8 + 0x58))
            (u_AmiHardwareSignatureSetupUpdateC_000aa7c0,&DAT_00095568,3,4,local_res8);
  return;
}

