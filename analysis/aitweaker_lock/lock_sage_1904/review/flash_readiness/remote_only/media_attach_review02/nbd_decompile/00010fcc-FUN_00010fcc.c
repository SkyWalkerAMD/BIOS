
void FUN_00010fcc(uint param_1,int param_2)

{
  int iVar1;
  fd_set *__readfds;
  uint uVar2;
  fd_set *__writefds;
  uint uVar3;
  __suseconds_t *p_Var4;
  timeval local_b0;
  fd_set local_a8;
  
  uVar3 = param_1 + 0x1f;
  if (-1 < (int)param_1) {
    uVar3 = param_1;
  }
  uVar2 = param_1 & 0x1f;
  iVar1 = (int)uVar3 >> 5;
  if (-1 < (int)-param_1) {
    uVar2 = -(-param_1 & 0x1f);
  }
  uVar3 = 1 << (uVar2 & 0xff);
  do {
    p_Var4 = &local_b0.tv_usec;
    do {
      p_Var4 = p_Var4 + 1;
      *p_Var4 = 0;
    } while (p_Var4 != local_a8.fds_bits + 0x1f);
    local_a8.fds_bits[iVar1] = local_a8.fds_bits[iVar1] | uVar3;
    if (param_2 == 1) {
      __readfds = &local_a8;
      __writefds = (fd_set *)0x0;
    }
    else {
      __readfds = (fd_set *)0x0;
      __writefds = &local_a8;
    }
    local_b0.tv_usec = 0;
    local_b0.tv_sec = 2;
    select(param_1 + 1,__readfds,__writefds,(fd_set *)0x0,&local_b0);
  } while ((uVar3 & local_a8.fds_bits[iVar1]) == 0);
  if ((*DAT_000110c4 & 1) != 0) {
    memcpy(&stack0xfffffec8,&local_a8,0x80);
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000110d8,DAT_000110d4,DAT_000110d0);
  }
  return;
}

