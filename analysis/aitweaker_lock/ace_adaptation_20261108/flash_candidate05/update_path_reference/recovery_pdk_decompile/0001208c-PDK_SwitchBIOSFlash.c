
undefined4 PDK_SwitchBIOSFlash(int param_1)

{
  FILE *__stream;
  int iVar1;
  long lVar2;
  undefined2 *__buf;
  size_t __n;
  undefined2 local_4c [2];
  undefined2 local_48 [2];
  undefined2 local_44;
  undefined1 local_42;
  char acStack_40 [4];
  undefined4 local_3c;
  char acStack_38 [40];
  
  memset(acStack_38,0,0x28);
  local_3c = *DAT_00012ef0;
  local_4c[0] = *DAT_00012ef4;
  local_48[0] = *DAT_00012ef8;
  local_44 = (undefined2)*DAT_00012eec;
  local_42 = (undefined1)((uint)*DAT_00012eec >> 0x10);
  __stream = fopen(DAT_00012f00,DAT_00012efc);
  if (__stream != (FILE *)0x0) {
    __isoc99_fscanf(__stream,DAT_00012f04,acStack_40);
    fclose(__stream);
  }
  if (param_1 == 0) {
    lVar2 = strtol(acStack_40,(char **)0x0,10);
    printf(DAT_00012f08,lVar2);
    lVar2 = strtol(acStack_40,(char **)0x0,10);
    if (lVar2 == 4) {
      memset(acStack_38,0,0x28);
      snprintf(acStack_38,0x28,DAT_00012f0c,0x2c);
      iVar1 = sigwrap_open(acStack_38,2);
      if (iVar1 < 0) {
        printf(DAT_00012f48,DAT_00012f10,DAT_00012f84);
        return 0xffffffff;
      }
      printf(DAT_00012f50,DAT_00012f10,0x2c,&local_3c);
      write(iVar1,&local_3c,3);
      sigwrap_close(iVar1);
      memset(acStack_38,0,0x28);
      snprintf(acStack_38,0x28,DAT_00012f1c,0x2c);
      iVar1 = sigwrap_open(acStack_38,2);
      if (iVar1 < 0) {
        printf(DAT_00012f48,DAT_00012f10,DAT_00012f80);
        return 0xffffffff;
      }
      printf(DAT_00012f54,DAT_00012f10,0x2c,local_4c);
      write(iVar1,local_4c,1);
      sigwrap_close(iVar1);
      sleep(1);
    }
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f0c,0x61);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f5c);
      return 0xffffffff;
    }
    printf(DAT_00012f14,DAT_00012f10,0x61,&local_44);
    write(iVar1,&local_44,2);
    sigwrap_close(iVar1);
    sleep(1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f0c,0xd);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f58);
      return 0xffffffff;
    }
    printf(DAT_00012f18,DAT_00012f10,0xd,&local_3c);
    write(iVar1,&local_3c,3);
    sigwrap_close(iVar1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f1c,0xd);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,0x1e0);
      return 0xffffffff;
    }
    printf(DAT_00012f20,DAT_00012f10,0xd,local_48);
    write(iVar1,local_48,1);
    sigwrap_close(iVar1);
    sleep(3);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f0c,0x62);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,0x1ec);
      return 0xffffffff;
    }
    printf(DAT_00012f24,DAT_00012f10,0x62,&local_3c);
    write(iVar1,&local_3c,3);
    sigwrap_close(iVar1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f1c,0x62);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f64);
      return 0xffffffff;
    }
    printf(DAT_00012f28,DAT_00012f10,0x62,local_4c);
    write(iVar1,local_4c,1);
    sigwrap_close(iVar1);
    sleep(1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f0c,0x65);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f68);
      return 0xffffffff;
    }
    printf(DAT_00012f2c,DAT_00012f10,0x65,&local_3c);
    write(iVar1,&local_3c,3);
    sigwrap_close(iVar1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f1c,0x65);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,0x20c);
      return 0xffffffff;
    }
    printf(DAT_00012f30,DAT_00012f10,0x65,local_48);
    write(iVar1,local_48,1);
    sigwrap_close(iVar1);
    sleep(1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f0c,0xf);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,0x218);
      return 0xffffffff;
    }
    printf(DAT_00012f34,DAT_00012f10,0xf,&local_3c);
    write(iVar1,&local_3c,3);
    sigwrap_close(iVar1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f1c,0xf);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f60);
      return 0xffffffff;
    }
    printf(DAT_00012f38,DAT_00012f10,0xf,local_4c);
    write(iVar1,local_4c,1);
    sigwrap_close(iVar1);
    sleep(1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f0c,5);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f6c);
      return 0xffffffff;
    }
    printf(DAT_00012f3c,DAT_00012f10,5,&local_3c);
    write(iVar1,&local_3c,3);
    sigwrap_close(iVar1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f1c,5);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,0x238);
      return 0xffffffff;
    }
  }
  else {
    if (param_1 == 1) {
      sleep(1);
      memset(acStack_38,0,0x28);
      snprintf(acStack_38,0x28,DAT_00012f0c,5);
      iVar1 = sigwrap_open(acStack_38,2);
      if (iVar1 < 0) {
        printf(DAT_00012f48,DAT_00012f10,0x248);
        return 0xffffffff;
      }
      printf(DAT_00012f3c,DAT_00012f10,5,&local_44);
      write(iVar1,&local_44,2);
      sigwrap_close(iVar1);
      sleep(1);
      memset(acStack_38,0,0x28);
      snprintf(acStack_38,0x28,DAT_00012f0c,0xf);
      iVar1 = sigwrap_open(acStack_38,2);
      if (iVar1 < 0) {
        printf(DAT_00012f48,DAT_00012f10,0x254);
        return 0xffffffff;
      }
      printf(DAT_00012f34,DAT_00012f10,0xf,&local_44);
      write(iVar1,&local_44,2);
      sigwrap_close(iVar1);
      sleep(1);
      memset(acStack_38,0,0x28);
      snprintf(acStack_38,0x28,DAT_00012f0c,0x65);
      iVar1 = sigwrap_open(acStack_38,2);
      if (iVar1 < 0) {
        printf(DAT_00012f48,DAT_00012f10,0x260);
        return 0xffffffff;
      }
      printf(DAT_00012f2c,DAT_00012f10,0x65,&local_44);
      write(iVar1,&local_44,2);
      sigwrap_close(iVar1);
      sleep(1);
      memset(acStack_38,0,0x28);
      snprintf(acStack_38,0x28,DAT_00012f0c,0xd);
      iVar1 = sigwrap_open(acStack_38,2);
      if (iVar1 < 0) {
        printf(DAT_00012f48,DAT_00012f10,0x26c);
        return 0xffffffff;
      }
      printf(DAT_00012f18,DAT_00012f10,0xd,&local_44);
      write(iVar1,&local_44,2);
      sigwrap_close(iVar1);
      sleep(3);
      memset(acStack_38,0,0x28);
      snprintf(acStack_38,0x28,DAT_00012f0c,0x61);
      iVar1 = sigwrap_open(acStack_38,2);
      if (iVar1 < 0) {
        printf(DAT_00012f48,DAT_00012f10,0x278);
        return 0xffffffff;
      }
      printf(DAT_00012f14,DAT_00012f10,0x61,&local_3c);
      write(iVar1,&local_3c,3);
      sigwrap_close(iVar1);
      memset(acStack_38,0,0x28);
      snprintf(acStack_38,0x28,DAT_00012f1c,0x61);
      iVar1 = sigwrap_open(acStack_38,2);
      if (iVar1 < 0) {
        printf(DAT_00012f48,DAT_00012f10,DAT_00012f70);
        return 0xffffffff;
      }
      printf(DAT_00012f4c,DAT_00012f10,0x61,local_4c);
      write(iVar1,local_4c,1);
      sigwrap_close(iVar1);
      sleep(1);
      lVar2 = strtol(acStack_40,(char **)0x0,10);
      if (lVar2 != 4) {
        return 0;
      }
      memset(acStack_38,0,0x28);
      snprintf(acStack_38,0x28,DAT_00012f0c,0x2c);
      iVar1 = sigwrap_open(acStack_38,2);
      if (iVar1 < 0) {
        printf(DAT_00012f48,DAT_00012f10,DAT_00012f94);
        return 0xffffffff;
      }
      printf(DAT_00012f50,DAT_00012f10,0x2c,&local_44);
      __buf = &local_44;
      __n = 2;
      goto LAB_000125c8;
    }
    if (param_1 != 2) {
      return 0;
    }
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f0c,0xf);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f74);
      return 0xffffffff;
    }
    printf(DAT_00012f34,DAT_00012f10,0xf,&local_44);
    write(iVar1,&local_44,2);
    sigwrap_close(iVar1);
    sleep(1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f0c,5);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f7c);
      return 0xffffffff;
    }
    printf(DAT_00012f3c,DAT_00012f10,5,&local_44);
    write(iVar1,&local_44,2);
    sigwrap_close(iVar1);
    sleep(1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f0c,0x62);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f78);
      return 0xffffffff;
    }
    printf(DAT_00012f24,DAT_00012f10,0x62,&local_44);
    write(iVar1,&local_44,2);
    sigwrap_close(iVar1);
    sleep(1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f0c,0xf);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f8c);
      return 0xffffffff;
    }
    printf(DAT_00012f34,DAT_00012f10,0xf,&local_3c);
    write(iVar1,&local_3c,3);
    sigwrap_close(iVar1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f1c,0xf);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f88);
      return 0xffffffff;
    }
    printf(DAT_00012f38,DAT_00012f10,0xf,local_4c);
    write(iVar1,local_4c,1);
    sigwrap_close(iVar1);
    sleep(1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f0c,5);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f90);
      return 0xffffffff;
    }
    printf(DAT_00012f3c,DAT_00012f10,5,&local_3c);
    write(iVar1,&local_3c,3);
    sigwrap_close(iVar1);
    memset(acStack_38,0,0x28);
    snprintf(acStack_38,0x28,DAT_00012f1c,5);
    iVar1 = sigwrap_open(acStack_38,2);
    if (iVar1 < 0) {
      printf(DAT_00012f48,DAT_00012f10,DAT_00012f44);
      return 0xffffffff;
    }
  }
  __buf = local_4c;
  printf(DAT_00012f40,DAT_00012f10,5,__buf);
  __n = 1;
LAB_000125c8:
  write(iVar1,__buf,__n);
  sigwrap_close(iVar1);
  sleep(1);
  return 0;
}

