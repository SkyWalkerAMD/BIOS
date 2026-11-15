
void FUN_00016fd0(uint param_1,undefined4 param_2)

{
  uint uVar1;
  uint *puVar2;
  uint uVar3;
  undefined4 local_98;
  uint local_94;
  uint local_90 [33];
  
  puVar2 = &local_94;
  do {
    puVar2 = puVar2 + 1;
    *puVar2 = 0;
  } while (puVar2 != local_90 + 0x1f);
  uVar3 = param_1 + 0x1f;
  if (-1 < (int)param_1) {
    uVar3 = param_1;
  }
  local_94 = 0;
  uVar1 = param_1 & 0x1f;
  if (-1 < (int)-param_1) {
    uVar1 = -(-param_1 & 0x1f);
  }
  local_90[(int)uVar3 >> 5] = local_90[(int)uVar3 >> 5] | 1 << (uVar1 & 0xff);
  local_98 = param_2;
  sigwrap_select(param_1 + 1,local_90,0,0,&local_98);
  return;
}

