
void sm_set_last_recv_time(int param_1)

{
  int *piVar1;
  int iVar2;
  sysinfo local_50;
  
  piVar1 = DAT_00021944;
  acquire_mutex(*DAT_00021944 + param_1 * 0x18);
  iVar2 = piVar1[1] + param_1 * 0x450;
  if (((*(int *)(iVar2 + 4) != 0) && (*(int *)(iVar2 + 8) != 0)) &&
     (iVar2 = sysinfo(&local_50), iVar2 == 0)) {
    *(long *)(piVar1[1] + param_1 * 0x450 + 0x440) = local_50.uptime;
  }
  release_mutex(*piVar1 + param_1 * 0x18);
  return;
}

