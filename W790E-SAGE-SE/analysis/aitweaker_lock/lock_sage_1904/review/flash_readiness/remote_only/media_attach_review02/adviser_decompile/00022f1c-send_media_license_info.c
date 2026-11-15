
void send_media_license_info(undefined4 param_1)

{
  undefined2 local_18;
  undefined2 local_16;
  undefined2 local_14;
  undefined2 local_12;
  
  local_12 = *DAT_00022f6c;
  local_18 = 0x35;
  local_16 = 0;
  local_14 = 0;
  sm_build_send_list();
  send_control_pkt(&local_18,param_1,0,0,0);
  return;
}

