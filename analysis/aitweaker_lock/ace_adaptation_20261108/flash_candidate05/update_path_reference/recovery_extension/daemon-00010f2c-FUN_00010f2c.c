/* Exact ELF literal/relocation map. */
{
  "000110fc": {
    "elf_va": "0x110fc",
    "file_offset": "0x10fc",
    "raw_u32": "0x23998",
    "target_elf_va": "0x23998"
  },
  "00011100": {
    "elf_va": "0x11100",
    "file_offset": "0x1100",
    "raw_u32": "0x230b4",
    "target_elf_va": "0x230b4"
  },
  "00011104": {
    "elf_va": "0x11104",
    "file_offset": "0x1104",
    "raw_u32": "0x23550",
    "target_elf_va": "0x23550"
  },
  "00011108": {
    "elf_va": "0x11108",
    "file_offset": "0x1108",
    "raw_u32": "0x239e0",
    "target_elf_va": "0x239e0"
  },
  "0001110c": {
    "elf_va": "0x1110c",
    "file_offset": "0x110c",
    "raw_u32": "0x123f0",
    "target_elf_va": "0x123f0",
    "target_string": "/usr/local/lib/compmanager/"
  },
  "00011110": {
    "elf_va": "0x11110",
    "file_offset": "0x1110",
    "raw_u32": "0x1240c",
    "target_elf_va": "0x1240c",
    "target_string": "g_CompMngrDynInfoTblcount %d\n"
  },
  "00011114": {
    "elf_va": "0x11114",
    "file_offset": "0x1114",
    "raw_u32": "0x239a4",
    "target_elf_va": "0x239a4"
  },
  "00011118": {
    "elf_va": "0x11118",
    "file_offset": "0x1118",
    "raw_u32": "0x1f6",
    "target_elf_va": "0x1f6"
  },
  "0001111c": {
    "elf_va": "0x1111c",
    "file_offset": "0x111c",
    "raw_u32": "0x11f94",
    "target_elf_va": "0x11f94",
    "target_string": "compmanager.c"
  },
  "00011120": {
    "elf_va": "0x11120",
    "file_offset": "0x1120",
    "raw_u32": "0x1242c",
    "target_elf_va": "0x1242c",
    "target_string": "[%s:%d]Error in thread creation for comp_mngr_worker \n"
  },
  "00011124": {
    "elf_va": "0x11124",
    "file_offset": "0x1124",
    "raw_u32": "0x121f8",
    "target_elf_va": "0x121f8",
    "target_string": "/var/pipe/comp_req_pipe"
  },
  "00011128": {
    "elf_va": "0x11128",
    "file_offset": "0x1128",
    "raw_u32": "0x124a4",
    "target_elf_va": "0x124a4",
    "target_string": "/var/pipe/comp_res_pipe"
  },
  "0001112c": {
    "elf_va": "0x1112c",
    "file_offset": "0x112c",
    "raw_u32": "0x11bcc",
    "target_elf_va": "0x11bcc"
  },
  "00011130": {
    "elf_va": "0x11130",
    "file_offset": "0x1130",
    "raw_u32": "0x12558",
    "target_elf_va": "0x12558",
    "target_string": "compmanager Go to sleep mode"
  },
  "00011134": {
    "elf_va": "0x11134",
    "file_offset": "0x1134",
    "raw_u32": "0x123bc",
    "target_elf_va": "0x123bc",
    "target_string": "[%s:%d]Initialization of component manager failed \n"
  },
  "00011138": {
    "elf_va": "0x11138",
    "file_offset": "0x1138",
    "raw_u32": "0x209",
    "target_elf_va": "0x209"
  },
  "0001113c": {
    "elf_va": "0x1113c",
    "file_offset": "0x113c",
    "raw_u32": "0x124bc",
    "target_elf_va": "0x124bc",
    "target_string": "[%s:%d]Error while creating Component Manager Response FIFO\n"
  },
  "00011140": {
    "elf_va": "0x11140",
    "file_offset": "0x1140",
    "raw_u32": "0x216",
    "target_elf_va": "0x216"
  },
  "00011144": {
    "elf_va": "0x11144",
    "file_offset": "0x1144",
    "raw_u32": "0x12520",
    "target_elf_va": "0x12520",
    "target_string": "[%s:%d]Error in thread creation for comp_mngr_recvmsg \n"
  },
  "00011148": {
    "elf_va": "0x11148",
    "file_offset": "0x1148",
    "raw_u32": "0x203",
    "target_elf_va": "0x203"
  },
  "0001114c": {
    "elf_va": "0x1114c",
    "file_offset": "0x114c",
    "raw_u32": "0x12464",
    "target_elf_va": "0x12464",
    "target_string": "[%s:%d]Error while creating Component Manager Request FIFO \n"
  },
  "00011150": {
    "elf_va": "0x11150",
    "file_offset": "0x1150",
    "raw_u32": "0x124fc",
    "target_elf_va": "0x124fc",
    "target_string": "[%s:%d]Error opening named pipe %s\n"
  }
}

undefined4 FUN_00010f2c(void)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  pthread_t *__newthread;
  pthread_t pStack_24;
  
  iVar5 = unix_init();
  piVar1 = DAT_000110fc;
  if (iVar5 < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011134,DAT_0001111c,0x1e0);
  }
  else {
    RetrieveCoreFeatures(DAT_00011100);
    RetrieveCoreMacros(DAT_00011104,DAT_00011100);
    FUN_00011ec0();
    GetCompLibraryMetaData(DAT_0001110c,DAT_00011108,piVar1);
    printf(DAT_00011110,*piVar1);
    uVar4 = DAT_00011120;
    uVar3 = DAT_0001111c;
    uVar2 = DAT_00011118;
    if (0 < *piVar1) {
      iVar7 = 0;
      iVar5 = DAT_00011108;
      __newthread = DAT_00011114;
      do {
        iVar7 = iVar7 + 1;
        if ((*(__start_routine **)(iVar5 + 0x110) != (__start_routine *)0x0) &&
           (iVar6 = pthread_create(__newthread,(pthread_attr_t *)0x0,
                                   *(__start_routine **)(iVar5 + 0x110),(void *)0x0), iVar6 != 0)) {
          IDBG_LINUXAPP_DbgOut(0x82,uVar4,uVar3,uVar2);
        }
        iVar5 = iVar5 + 0x114;
        __newthread = __newthread + 1;
      } while (iVar7 < *piVar1);
    }
    if (*(int *)(DAT_00011100 + 0x1b0) == 1) {
      FUN_00011540();
    }
    uVar2 = DAT_00011124;
    iVar5 = FUN_000114d8(DAT_00011124);
    if (iVar5 < 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001114c,DAT_0001111c,DAT_00011148);
    }
    else {
      iVar5 = FUN_000114d8(DAT_00011128);
      if (iVar5 < 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0001113c,DAT_0001111c,DAT_00011138);
      }
      else {
        iVar5 = sigwrap_open(uVar2,2);
        piVar1[1] = iVar5;
        if (iVar5 == -1) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00011150,DAT_0001111c,0x210,uVar2);
        }
        else {
          iVar5 = pthread_create(&pStack_24,(pthread_attr_t *)0x0,DAT_0001112c,(void *)0x0);
          if (iVar5 == 0) {
            puts(DAT_00011130);
            do {
              pcie_log();
              sleep(5);
            } while( true );
          }
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00011144,DAT_0001111c,DAT_00011140);
        }
      }
    }
  }
  return 0xffffffff;
}

