/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00010f40": {
    "elf_va": "0xf40",
    "file_offset": "0xf40",
    "raw_u32": "0x13c0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x13c0",
    "target_string": "[%s:%d] Lock the CompMngr mutex"
  },
  "00010f44": {
    "elf_va": "0xf44",
    "file_offset": "0xf44",
    "raw_u32": "0x13a4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x13a4",
    "target_string": "component_manager_helper.c"
  },
  "00010f48": {
    "elf_va": "0xf48",
    "file_offset": "0xf48",
    "raw_u32": "0x13e0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x13e0",
    "target_string": "/var/compmngr_mutex"
  },
  "00010f4c": {
    "elf_va": "0xf4c",
    "file_offset": "0xf4c",
    "raw_u32": "0x13f4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x13f4",
    "target_string": "[%s:%d]opening CompMngr Request Pipe"
  },
  "00010f50": {
    "elf_va": "0xf50",
    "file_offset": "0xf50",
    "raw_u32": "0x141c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x141c",
    "target_string": "/var/pipe/comp_req_pipe"
  },
  "00010f54": {
    "elf_va": "0xf54",
    "file_offset": "0xf54",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00010f58": {
    "elf_va": "0xf58",
    "file_offset": "0xf58",
    "raw_u32": "0x1434",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1434",
    "target_string": "[%s:%d]Write the command to Request Pipe"
  },
  "00010f5c": {
    "elf_va": "0xf5c",
    "file_offset": "0xf5c",
    "raw_u32": "0x1460",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1460",
    "target_string": "[%s:%d]Opening the CompMngr Response Pipe"
  },
  "00010f60": {
    "elf_va": "0xf60",
    "file_offset": "0xf60",
    "raw_u32": "0x148c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x148c",
    "target_string": "/var/pipe/comp_res_pipe"
  },
  "00010f64": {
    "elf_va": "0xf64",
    "file_offset": "0xf64",
    "raw_u32": "0x14a4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x14a4",
    "target_string": "[%s:%d]Wait to read the response from CompMngr"
  },
  "00010f68": {
    "elf_va": "0xf68",
    "file_offset": "0xf68",
    "raw_u32": "0x1534",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1534",
    "target_string": "[%s:%d]Retry now..\n"
  },
  "00010f6c": {
    "elf_va": "0xf6c",
    "file_offset": "0xf6c",
    "raw_u32": "0x1564",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1564",
    "target_string": "Error reading response %d\n"
  },
  "00010f70": {
    "elf_va": "0xf70",
    "file_offset": "0xf70",
    "raw_u32": "0x1548",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1548",
    "target_string": "Error no got retry again"
  },
  "00010f74": {
    "elf_va": "0xf74",
    "file_offset": "0xf74",
    "raw_u32": "0x14d4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x14d4",
    "target_string": "send_compmngr_command : Error waiting on Queue [Error : %s, Queue : response, Timeout : %d]\n"
  }
}
*/

undefined4 send_compmngr_command(short *param_1,short *param_2,uint param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int *piVar7;
  char *pcVar8;
  uint uVar9;
  undefined4 uVar10;
  uint uVar11;
  uint *puVar12;
  uint local_b0 [35];
  
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00010f40,DAT_00010f44,0x18);
  uVar2 = mutex_create_recursive(DAT_00010f48);
  iVar3 = mutex_lock_recursive(uVar2,10);
  if (iVar3 != 0) {
    mutex_destroy_recursive(uVar2);
    return 1;
  }
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00010f4c,DAT_00010f44,0x22);
  iVar4 = sigwrap_open(DAT_00010f50,1);
  iVar3 = DAT_00010f54;
  if (iVar4 == -1) {
    uVar10 = 0xfffffffe;
  }
  else {
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00010f58,DAT_00010f44,0x2b);
    iVar5 = sigwrap_write(iVar4,param_1,iVar3);
    if (iVar5 == iVar3) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00010f5c,DAT_00010f44,0x36);
      uVar6 = sigwrap_open(DAT_00010f60,2);
      if (uVar6 == 0xffffffff) {
        sigwrap_close(iVar4);
        uVar10 = 0xffffffff;
      }
      else {
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00010f64,DAT_00010f44,0x40);
        uVar1 = DAT_00010f68;
        uVar10 = DAT_00010f44;
        uVar9 = uVar6 + 0x1f;
        if (-1 < (int)uVar6) {
          uVar9 = uVar6;
        }
        uVar11 = uVar6 & 0x1f;
        if (-1 < (int)-uVar6) {
          uVar11 = -(-uVar6 & 0x1f);
        }
        while( true ) {
          if (-1 < (int)param_3) {
            puVar12 = local_b0 + 1;
            do {
              puVar12 = puVar12 + 1;
              *puVar12 = 0;
            } while (local_b0 + 0x21 != puVar12);
            local_b0[1] = 0;
            local_b0[((int)uVar9 >> 5) + 2] = local_b0[((int)uVar9 >> 5) + 2] | 1 << (uVar11 & 0xff)
            ;
            local_b0[0] = param_3;
            iVar3 = sigwrap_select(uVar6 + 1,local_b0 + 2,0,0,local_b0);
            if (iVar3 == -1) {
              piVar7 = __errno_location();
              pcVar8 = strerror(*piVar7);
              printf(DAT_00010f74,pcVar8,param_3);
              sigwrap_close(iVar4);
              sigwrap_close(uVar6);
              uVar10 = 0xffffffff;
              goto LAB_00010cec;
            }
            if (iVar3 == 0) {
              sigwrap_close(iVar4);
              sigwrap_close(uVar6);
              uVar10 = 0xfffffffd;
              goto LAB_00010cec;
            }
          }
          iVar3 = sigwrap_read(uVar6,param_2,DAT_00010f54);
          if (iVar3 == iVar5) {
            uVar10 = 0;
            if (*param_1 != *param_2) {
              uVar10 = 0xffffffff;
            }
            sigwrap_close(iVar4);
            sigwrap_close(uVar6);
            goto LAB_00010cec;
          }
          if (iVar3 != 0) break;
          IDBG_LINUXAPP_Runtime_DbgOut(0x87,uVar1,uVar10,0x69);
        }
        piVar7 = __errno_location();
        if (*piVar7 == 0xb || *piVar7 == 4) {
          puts(DAT_00010f70);
        }
        printf(DAT_00010f6c,iVar3);
        sigwrap_close(iVar4);
        sigwrap_close(uVar6);
        uVar10 = 0xffffffff;
      }
    }
    else {
      sigwrap_close(iVar4);
      uVar10 = 0xffffffff;
    }
  }
LAB_00010cec:
  mutex_unlock_recursive(uVar2);
  mutex_destroy_recursive(uVar2);
  return uVar10;
}

