/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00011374": {
    "elf_va": "0x1374",
    "file_offset": "0x1374",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "alphasort",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "DAT_or_PTR_00011378": {
    "elf_va": "0x1378",
    "file_offset": "0x1378",
    "raw_u32": "0x1644",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1644",
    "target_string": "GetCompMngrMetaLibInfo"
  },
  "DAT_or_PTR_0001137c": {
    "elf_va": "0x137c",
    "file_offset": "0x137c",
    "raw_u32": "0x16f4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x16f4",
    "target_string": "%s"
  },
  "DAT_or_PTR_00011380": {
    "elf_va": "0x1380",
    "file_offset": "0x1380",
    "raw_u32": "0x13a8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x13a8",
    "target_string": "component_manager_helper.c"
  },
  "DAT_or_PTR_00011384": {
    "elf_va": "0x1384",
    "file_offset": "0x1384",
    "raw_u32": "0x16f8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x16f8",
    "target_string": "[%s:%d]loading the library %s\n"
  },
  "DAT_or_PTR_00011388": {
    "elf_va": "0x1388",
    "file_offset": "0x1388",
    "raw_u32": "0x1680",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1680",
    "target_string": "[%s:%d]Error while getting the symbol name %s for component %s"
  },
  "DAT_or_PTR_0001138c": {
    "elf_va": "0x138c",
    "file_offset": "0x138c",
    "raw_u32": "0x105",
    "target_elf_va": "0x105"
  },
  "DAT_or_PTR_00011390": {
    "elf_va": "0x1390",
    "file_offset": "0x1390",
    "raw_u32": "0x16c0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x16c0",
    "target_string": "[%s:%d]Error While registering the component plugin %s"
  },
  "DAT_or_PTR_00011394": {
    "elf_va": "0x1394",
    "file_offset": "0x1394",
    "raw_u32": "0x165c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x165c",
    "target_string": "[%s:%d]Error in getting symbol %s \n"
  },
  "DAT_or_PTR_00011398": {
    "elf_va": "0x1398",
    "file_offset": "0x1398",
    "raw_u32": "0x1618",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1618",
    "target_string": "[%s:%d]Error in loading IPMI library %s\n"
  },
  "DAT_or_PTR_0001139c": {
    "elf_va": "0x139c",
    "file_offset": "0x139c",
    "raw_u32": "0x15e8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x15e8",
    "target_string": "[%s:%d]Error, unable to find any files in %s\n"
  }
}
*/

undefined4 GetCompLibraryMetaData(char *param_1,int param_2,int *param_3)

{
  dirent **ppdVar1;
  int iVar2;
  int iVar3;
  code *pcVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  dirent *pdVar9;
  int iVar10;
  dirent **ppdVar11;
  int iVar12;
  int iVar13;
  int local_3c;
  dirent **local_30;
  int local_2c [2];
  
  iVar13 = 0;
  local_2c[0] = 0;
  iVar2 = scandir(param_1,&local_30,(__selector *)0x0,DAT_00011374);
  if (iVar2 < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001139c,DAT_00011380,0xc2,param_1);
    uVar8 = 0xffffffff;
  }
  else {
    ppdVar11 = local_30;
    ppdVar1 = local_30;
    if (iVar2 != 0) {
      do {
        while( true ) {
          local_30 = ppdVar1;
          pdVar9 = ppdVar11[iVar13];
          iVar3 = IsValidLib(pdVar9->d_name);
          ppdVar1 = local_30;
          if (iVar3 != 0) break;
joined_r0x0001134c:
          local_30 = ppdVar11;
          iVar13 = iVar13 + 1;
          ppdVar11 = local_30;
          if (iVar13 == iVar2) goto LAB_0001127c;
        }
        iVar3 = dlopen(pdVar9->d_name,2);
        if (iVar3 == 0) {
          uVar8 = dlerror();
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00011398,DAT_00011380,0xd4,uVar8);
          ppdVar11 = local_30;
          ppdVar1 = local_30;
          goto joined_r0x0001134c;
        }
        pcVar4 = (code *)dlsym(iVar3,DAT_00011378);
        if (pcVar4 != (code *)0x0) {
          iVar5 = (*pcVar4)(local_2c);
          if (iVar5 != 0) {
            iVar10 = 0;
            local_3c = 0;
            iVar12 = 0;
            do {
              pcVar4 = (code *)dlsym(iVar3,local_2c[0] + iVar10 + 0x100);
              if (pcVar4 == (code *)0x0) {
                uVar8 = 0xe7;
                iVar6 = local_2c[0] + iVar10;
                iVar7 = iVar6 + 0x100;
LAB_00011228:
                IDBG_LINUXAPP_DbgOut(0x82,DAT_00011388,DAT_00011380,uVar8,iVar7,iVar6 + 1);
                local_3c = -1;
              }
              else {
                snprintf((char *)(param_2 + *param_3 * 0x114),0xff,DAT_0001137c,
                         local_2c[0] + iVar10 + 1);
                *(undefined1 *)(param_2 + *param_3 * 0x114 + 0xff) =
                     *(undefined1 *)(local_2c[0] + iVar10);
                iVar7 = dlsym(iVar3,local_2c[0] + iVar10 + 0x1ff);
                if (iVar7 == 0) {
                  uVar8 = 0xfb;
                  iVar6 = local_2c[0] + iVar10;
                  iVar7 = iVar6 + 0x1ff;
                  goto LAB_00011228;
                }
                *(int *)(param_2 + *param_3 * 0x114 + 0x108) = iVar7;
                iVar7 = (*pcVar4)(param_2 + *param_3 * 0x114);
                if (iVar7 == 0) {
                  *(int *)(param_2 + *param_3 * 0x114 + 0x100) = iVar3;
                  iVar7 = param_2 + *param_3 * 0x114;
                  if (*(code **)(iVar7 + 0x104) != (code *)0x0) {
                    (**(code **)(iVar7 + 0x104))();
                    iVar7 = param_2 + *param_3 * 0x114;
                  }
                  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011384,DAT_00011380,0x110,iVar7);
                  *param_3 = *param_3 + 1;
                }
                else {
                  IDBG_LINUXAPP_DbgOut
                            (0x82,DAT_00011390,DAT_00011380,DAT_0001138c,param_2 + *param_3 * 0x114)
                  ;
                  local_3c = -1;
                }
              }
              iVar12 = iVar12 + 1;
              iVar10 = iVar10 + 0x2fe;
            } while (iVar5 != iVar12);
            if (local_3c != 0) {
              dlclose(iVar3);
            }
          }
          free(local_30[iVar13]);
          ppdVar11 = local_30;
          ppdVar1 = local_30;
          goto joined_r0x0001134c;
        }
        uVar8 = dlerror();
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00011394,DAT_00011380,0xdb,uVar8);
        dlclose(iVar3);
        iVar13 = iVar13 + 1;
        ppdVar11 = local_30;
        ppdVar1 = local_30;
      } while (iVar13 != iVar2);
    }
LAB_0001127c:
    free(local_30);
    uVar8 = 0;
  }
  return uVar8;
}

