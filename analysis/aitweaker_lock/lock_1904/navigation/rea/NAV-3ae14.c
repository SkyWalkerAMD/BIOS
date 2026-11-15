
void Candidate_BrowserStartHook(void)

{
  undefined1 local_res8 [32];
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_18 = 0xec87d643;
  local_14 = 0x4bb5eba4;
  local_10 = 0x3e3fe5a1;
  local_c = 0xa90db236;
  local_res8[0] = 0;
  (**(code **)(DAT_00082a80 + 0x58))(u_VgaNotFoundFlag_0007ce98,&local_18,1,0,local_res8);
  return;
}

