
void PrintBiosHeader(void *param_1)

{
  int iVar1;
  char *__format;
  char *__format_00;
  char *__format_01;
  int iVar2;
  uint uVar3;
  undefined1 auStack_40 [8];
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined2 local_24;
  undefined1 local_22;
  
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  local_28 = 0;
  local_24 = 0;
  local_22 = 0;
  memcpy(auStack_40,param_1,9);
  printf(DAT_00012cb0,9,auStack_40);
  printf(DAT_00012cb4,1,(uint)*(byte *)((int)param_1 + 9));
  printf(DAT_00012cb8,1,(uint)*(byte *)((int)param_1 + 10));
  printf(DAT_00012cbc,1,(uint)*(byte *)((int)param_1 + 0xb));
  printf(DAT_00012cc0,1,(uint)*(byte *)((int)param_1 + 0xc));
  printf(DAT_00012cc4,1,(uint)*(byte *)((int)param_1 + 0xd));
  local_22 = 0;
  memcpy(auStack_40,(void *)((int)param_1 + 0xe),0x1e);
  printf(DAT_00012cc8,0x1e,auStack_40);
  local_22 = 0;
  memcpy(auStack_40,(void *)((int)param_1 + 0x2c),0x1e);
  printf(DAT_00012ccc,0x1e,auStack_40);
  local_2c = 0;
  local_28 = 0;
  local_24 = 0;
  local_22 = 0;
  memcpy(auStack_40,(void *)((int)param_1 + 0x4a),0x14);
  printf(DAT_00012cd0,0x14,auStack_40);
  printf(DAT_00012cd4,1,(uint)*(byte *)((int)param_1 + 0x5e));
  memset((void *)((int)&local_38 + 2),0,0x15);
  memcpy(auStack_40,(void *)((int)param_1 + 0x5f),0xb);
  printf(DAT_00012cd8,0xb,auStack_40);
  memset((void *)((int)&local_38 + 2),0,0x15);
  memcpy(auStack_40,(void *)((int)param_1 + 0x6a),10);
  printf(DAT_00012cdc,10,auStack_40);
  printf(DAT_00012ce0,1,(uint)*(byte *)((int)param_1 + 0x74));
  printf(DAT_00012ce4,4,*(undefined4 *)((int)param_1 + 0x75));
  printf(DAT_00012ce8,4,*(undefined4 *)((int)param_1 + 0x79));
  printf(DAT_00012cec,4,*(undefined4 *)((int)param_1 + 0x7d));
  printf(DAT_00012cf0,4,*(undefined4 *)((int)param_1 + 0x81));
  printf(DAT_00012cf4,4,*(undefined4 *)((int)param_1 + 0x85));
  printf(DAT_00012cf8,4,*(undefined4 *)((int)param_1 + 0x89));
  printf(DAT_00012cfc,4,*(undefined4 *)((int)param_1 + 0x8d));
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  local_28 = 0;
  local_24 = 0;
  local_22 = 0;
  memcpy(auStack_40,(void *)((int)param_1 + 0x91),0xc);
  printf(DAT_00012d00,0xc,auStack_40);
  printf(DAT_00012d04,2,(uint)*(ushort *)((int)param_1 + 0x9d));
  printf(DAT_00012d08,4,*(undefined4 *)((int)param_1 + 0x9f));
  printf(DAT_00012d0c,4,*(undefined4 *)((int)param_1 + 0xa3));
  printf(DAT_00012d10,4,*(undefined4 *)((int)param_1 + 0xa7));
  printf(DAT_00012d14,4,*(undefined4 *)((int)param_1 + 0xab));
  printf(DAT_00012d18,4,*(undefined4 *)((int)param_1 + 0xc3));
  printf(DAT_00012d1c,4,*(undefined4 *)((int)param_1 + 199));
  printf(DAT_00012d20,*(undefined4 *)((int)param_1 + 0xaf));
  if (*(int *)((int)param_1 + 0xaf) != 0) {
    printf(DAT_00012d24,*(undefined4 *)((int)param_1 + 0xb3));
    printf(DAT_00012d28,*(undefined4 *)((int)param_1 + 0xb7));
  }
  printf(DAT_00012d2c,*(undefined4 *)((int)param_1 + 0xbb));
  printf(DAT_00012d30,*(undefined4 *)((int)param_1 + 0xbf));
  __format_01 = DAT_00012d34;
  __format_00 = DAT_00012d28;
  __format = DAT_00012d24;
  iVar2 = *(int *)((int)param_1 + 0xcb);
  if ((iVar2 != 0) && (*(int *)((int)param_1 + 0xbb) != 0)) {
    uVar3 = 0;
    while( true ) {
      iVar1 = uVar3 * 9;
      printf(__format_01,(uint)*(byte *)(iVar2 + iVar1));
      printf(__format,*(undefined4 *)(*(int *)((int)param_1 + 0xcb) + iVar1 + 1));
      printf(__format_00,*(undefined4 *)(*(int *)((int)param_1 + 0xcb) + iVar1 + 5));
      uVar3 = uVar3 + 1;
      if (*(uint *)((int)param_1 + 0xbb) <= uVar3) break;
      iVar2 = *(int *)((int)param_1 + 0xcb);
    }
  }
  return;
}

