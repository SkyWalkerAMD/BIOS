
undefined4 bios_start_update(undefined2 *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined4 *__arg;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  pthread_t pStack_10060;
  uint uStack_1005c;
  undefined2 auStack_10058 [2];
  int iStack_10054;
  undefined2 uStack_10050;
  char local_4c [32];
  uint local_2c;
  
  iVar3 = DAT_0001405c;
  local_2c = **(uint **)(DAT_00014054 + 0x13db0 + DAT_00014058);
  local_4c[0] = '\0';
  local_4c[1] = '\0';
  local_4c[2] = '\0';
  local_4c[3] = '\0';
  memset(local_4c + 4,0,0x1c);
  uStack_1005c = 0;
  memset((void *)(DAT_00014060 + 0x13e34),0,0x20);
  memset(auStack_10058,0,DAT_00014064);
  if (**(int **)(iVar3 + 0x13e1c + DAT_00014068) != *(int *)(param_1 + 5)) {
    iStack_10054 = 6;
    goto LAB_00013edc;
  }
  uVar4 = *(uint *)(param_1 + 9);
  uVar6 = *(undefined4 *)(param_1 + 7);
  iVar5 = *(int *)(param_1 + 0xb);
  strcpy(local_4c,(char *)(DAT_0001406c + 0x13e64));
  uVar2 = uVar4;
  iVar7 = iVar5;
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00014074 + 0x13e94,DAT_00014070 + 0x13f5c,uVar6,uVar4,iVar5);
  iVar1 = get_bios_file_size(&uStack_1005c,local_4c);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001407c + 0x13ed0,DAT_00014078 + 0x13ecc,0x44f,uVar2,iVar7);
    uStack_10050 = 0;
    iStack_10054 = 0xff;
    goto LAB_00013edc;
  }
  if (uVar4 < uStack_1005c) {
    uVar6 = 0x474;
    iVar1 = DAT_00014084 + 0x13f64;
    iVar3 = DAT_00014088 + 0x13f68;
LAB_00013f64:
    IDBG_LINUXAPP_DbgOut(0x82,iVar3,iVar1,uVar6,uVar2,iVar7);
    uStack_10050 = 0;
    iStack_10054 = 0xff;
  }
  else {
    if (iVar5 == 0xff) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00014094 + 0x13fb8);
    }
    else {
      iVar1 = BiosConfiguration();
      if (iVar1 != 0) {
        uVar6 = 0x485;
        iVar1 = DAT_0001408c + 0x13fa4;
        iVar3 = DAT_00014090 + 0x13fa8;
        goto LAB_00013f64;
      }
    }
    IDBG_LINUXAPP_DbgOut
              (0x86,DAT_0001409c + 0x13fd8,(int)&DAT_000140a0 + DAT_00014098,uVar6,uStack_1005c,
               iVar7);
    iVar7 = DAT_000140a0;
    __arg = (undefined4 *)(DAT_000140a0 + 0x14018);
    *(uint *)(DAT_000140a0 + 0x1401c) = uStack_1005c;
    *__arg = uVar6;
    *(undefined4 *)(iVar7 + 0x14024) = *(undefined4 *)(param_1 + 2);
    iVar1 = DAT_000140a4;
    *(int *)(iVar7 + 0x14020) = iVar5;
    iStack_10054 = pthread_create(&pStack_10060,(pthread_attr_t *)0x0,
                                  *(__start_routine **)(iVar3 + 0x13e1c + iVar1),__arg);
    if (iStack_10054 != 0) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000140a8 + 0x14034);
    }
    uStack_10050 = 0;
  }
LAB_00013edc:
  if (iStack_10054 != 0) {
    Getpdklib(2);
    Getpdklib(2);
    ActiveHostSPIDriver(1);
  }
  auStack_10058[0] = *param_1;
  uVar6 = send_compmngr_response(auStack_10058);
  uVar2 = local_2c ^ **(uint **)(DAT_00014080 + 0x13f28 + DAT_00014058);
  if (uVar2 == 0) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar6,uVar2,0);
}

