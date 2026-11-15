
void Candidate_SetupEnterSignal(void)

{
  longlong lVar1;
  undefined1 local_res8 [8];
  undefined8 local_res10 [3];
  undefined4 local_278;
  undefined4 local_274;
  undefined4 local_270;
  undefined4 local_26c;
  undefined1 local_268 [86];
  char local_212;
  
  local_278 = 0xec87d643;
  local_274 = 0x4bb5eba4;
  local_270 = 0x3e3fe5a1;
  local_26c = 0xa90db236;
  local_res10[0] = 600;
  lVar1 = (**(code **)(DAT_00082a80 + 0x48))
                    (u_Setup_0007c350,&local_278,local_res8,local_res10,local_268);
  if ((lVar1 < 0) || (local_212 != '\0')) {
    FUN_000064e4(&DAT_0006a230);
  }
  return;
}

