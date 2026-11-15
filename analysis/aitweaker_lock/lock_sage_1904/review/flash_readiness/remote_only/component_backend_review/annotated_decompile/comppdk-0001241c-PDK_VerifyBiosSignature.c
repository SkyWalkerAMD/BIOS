/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00012880": {
    "elf_va": "0x2880",
    "file_offset": "0x2880",
    "raw_u32": "0x34ac",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x34ac",
    "target_string": "PDK_SwitchBIOSFlash"
  },
  "DAT_or_PTR_00012884": {
    "elf_va": "0x2884",
    "file_offset": "0x2884",
    "raw_u32": "0x397c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x397c",
    "target_string": "/var/bios.bin"
  },
  "DAT_or_PTR_00012888": {
    "elf_va": "0x2888",
    "file_offset": "0x2888",
    "raw_u32": "0x398c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x398c",
    "target_string": "/var/biossig.bin"
  },
  "DAT_or_PTR_0001288c": {
    "elf_va": "0x288c",
    "file_offset": "0x288c",
    "raw_u32": "0x39d4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x39d4",
    "target_string": "[PDK_VerifyBiosSignature] bios_size = %ld\n"
  },
  "DAT_or_PTR_00012890": {
    "elf_va": "0x2890",
    "file_offset": "0x2890",
    "raw_u32": "0x1001",
    "target_elf_va": "0x1001"
  },
  "DAT_or_PTR_00012894": {
    "elf_va": "0x2894",
    "file_offset": "0x2894",
    "raw_u32": "0x3a98",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3a98",
    "target_string": "SignCert verify success"
  },
  "DAT_or_PTR_00012898": {
    "elf_va": "0x2898",
    "file_offset": "0x2898",
    "raw_u32": "0xaaaaaaab",
    "target_elf_va": "0xaaaaaaab"
  },
  "DAT_or_PTR_0001289c": {
    "elf_va": "0x289c",
    "file_offset": "0x289c",
    "raw_u32": "0x3af8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3af8",
    "target_string": "[BIOS_ROM verify] EVP_DigestVerifyUpdate error %x %x\n"
  },
  "DAT_or_PTR_000128a0": {
    "elf_va": "0x28a0",
    "file_offset": "0x28a0",
    "raw_u32": "0x3b80",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3b80",
    "target_string": "BIOS_ROM verify failed"
  },
  "DAT_or_PTR_000128a4": {
    "elf_va": "0x28a4",
    "file_offset": "0x28a4",
    "raw_u32": "0x39a0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x39a0",
    "target_string": "[PDK_VerifyBiosSignature] read_file_append failed."
  },
  "DAT_or_PTR_000128a8": {
    "elf_va": "0x28a8",
    "file_offset": "0x28a8",
    "raw_u32": "0x3ab0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3ab0",
    "target_string": "SignCert verify failed"
  },
  "DAT_or_PTR_000128ac": {
    "elf_va": "0x28ac",
    "file_offset": "0x28ac",
    "raw_u32": "0x3b68",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3b68",
    "target_string": "BIOS_ROM verify success"
  },
  "DAT_or_PTR_000128b0": {
    "elf_va": "0x28b0",
    "file_offset": "0x28b0",
    "raw_u32": "0x3a30",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3a30",
    "target_string": "[SignCert verify] EVP_PKEY_CTX_set_rsa_padding error"
  },
  "DAT_or_PTR_000128b4": {
    "elf_va": "0x28b4",
    "file_offset": "0x28b4",
    "raw_u32": "0x3a00",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3a00",
    "target_string": "[SignCert verify] EVP_DigestVerifyInit error"
  },
  "DAT_or_PTR_000128b8": {
    "elf_va": "0x28b8",
    "file_offset": "0x28b8",
    "raw_u32": "0x3a68",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3a68",
    "target_string": "[SignCert verify] EVP_DigestVerifyUpdate error"
  },
  "DAT_or_PTR_000128bc": {
    "elf_va": "0x28bc",
    "file_offset": "0x28bc",
    "raw_u32": "0x3ac8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3ac8",
    "target_string": "[BIOS_ROM verify] EVP_DigestVerifyInit error"
  },
  "DAT_or_PTR_000128c0": {
    "elf_va": "0x28c0",
    "file_offset": "0x28c0",
    "raw_u32": "0x3b30",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3b30",
    "target_string": "[BIOS_ROM verify] EVP_DigestVerifyUpdate error rom_tbl"
  }
}
*/

undefined4 PDK_VerifyBiosSignature(void)

{
  ulonglong uVar1;
  void *pvVar2;
  int iVar3;
  RSA *pRVar4;
  BIGNUM *pBVar5;
  BIGNUM *pBVar6;
  EVP_PKEY *pEVar7;
  EVP_MD_CTX *pEVar8;
  EVP_MD *pEVar9;
  size_t sVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  void *pvVar14;
  void *d;
  undefined2 local_30;
  undefined1 local_2e;
  void *local_2c;
  undefined4 local_28;
  EVP_PKEY_CTX *local_24 [2];
  
  local_30 = (undefined2)*(undefined4 *)(DAT_00012880 + 0x14);
  local_2e = (undefined1)((uint)*(undefined4 *)(DAT_00012880 + 0x14) >> 0x10);
  local_24[0] = (EVP_PKEY_CTX *)0x0;
  iVar3 = read_file_append(DAT_00012888,DAT_00012884,&local_2c,&local_28);
  if (iVar3 < 0) {
    puts(DAT_000128a4);
joined_r0x0001273c:
    if (local_2c != (void *)0x0) {
      free(local_2c);
    }
  }
  else {
    printf(DAT_0001288c,local_28);
    pvVar2 = local_2c;
    pRVar4 = RSA_new();
    pBVar5 = BN_bin2bn((uchar *)((int)pvVar2 + 600),0x100,(BIGNUM *)0x0);
    pBVar6 = BN_bin2bn((uchar *)&local_30,3,(BIGNUM *)0x0);
    RSA_set0_key(pRVar4,pBVar5,pBVar6,0);
    pEVar7 = EVP_PKEY_new();
    EVP_PKEY_assign(pEVar7,6,pRVar4);
    pEVar8 = (EVP_MD_CTX *)EVP_MD_CTX_new();
    local_24[0] = EVP_PKEY_CTX_new(pEVar7,(ENGINE *)0x0);
    pEVar9 = EVP_sha256();
    iVar3 = EVP_DigestVerifyInit(pEVar8,local_24,pEVar9,(ENGINE *)0x0,pEVar7);
    if (iVar3 < 1) {
      puts(DAT_000128b4);
      goto joined_r0x0001273c;
    }
    iVar3 = RSA_pkey_ctx_ctrl(local_24[0],0xffffffff,DAT_00012890,6,0);
    if (iVar3 < 1) {
LAB_000127b4:
      puts(DAT_000128b0);
      goto joined_r0x0001273c;
    }
    iVar3 = EVP_DigestUpdate(pEVar8,(void *)((int)pvVar2 + 0x20),0x228);
    if (iVar3 < 1) {
      puts(DAT_000128b8);
      goto joined_r0x0001273c;
    }
    iVar3 = EVP_DigestVerifyFinal(pEVar8,(uchar *)((int)pvVar2 + 0x358),0x100);
    EVP_MD_CTX_free(pEVar8);
    if (iVar3 == 1) {
      puts(DAT_00012894);
      pRVar4 = RSA_new();
      pBVar5 = BN_bin2bn((uchar *)((int)pvVar2 + 0x48),0x100,(BIGNUM *)0x0);
      pBVar6 = BN_bin2bn((uchar *)&local_30,3,(BIGNUM *)0x0);
      RSA_set0_key(pRVar4,pBVar5,pBVar6,0);
      pEVar7 = EVP_PKEY_new();
      EVP_PKEY_assign(pEVar7,6,pRVar4);
      pEVar8 = (EVP_MD_CTX *)EVP_MD_CTX_new();
      local_24[0] = EVP_PKEY_CTX_new(pEVar7,(ENGINE *)0x0);
      pEVar9 = EVP_sha256();
      iVar3 = EVP_DigestVerifyInit(pEVar8,local_24,pEVar9,(ENGINE *)0x0,pEVar7);
      if (iVar3 < 1) {
        puts(DAT_000128bc);
      }
      else {
        iVar3 = RSA_pkey_ctx_ctrl(local_24[0],0xffffffff,DAT_00012890,6,0);
        if (iVar3 < 1) goto LAB_000127b4;
        uVar11 = (uint)*(ushort *)((int)pvVar2 + 0x1c) - (uint)*(ushort *)((int)pvVar2 + 0x1e);
        uVar1 = (ulonglong)DAT_00012898;
        d = (void *)((int)local_2c + (uint)*(ushort *)((int)pvVar2 + 0x1e));
        if ((uVar11 < 0x18) ||
           (sVar10 = *(size_t *)((int)d + 0xc), uVar12 = 0, pvVar14 = d, sVar10 == 0)) {
          sVar10 = 0x18;
        }
        else {
          do {
            uVar13 = uVar12;
            if (((*(byte *)((int)pvVar14 + 0x15) & 2) != 0) &&
               (iVar3 = EVP_DigestUpdate(pEVar8,(void *)((int)local_2c +
                                                        (uint)*(ushort *)((int)pvVar2 + 0x1c) +
                                                        *(int *)((int)pvVar14 + 8)),sVar10),
               iVar3 < 1)) {
              printf(DAT_0001289c,*(undefined4 *)((int)pvVar14 + 8),
                     *(undefined4 *)((int)pvVar14 + 0xc));
              goto joined_r0x0001273c;
            }
            uVar12 = uVar13 + 1;
          } while (((uint)(uVar1 * uVar11 >> 0x24) != uVar12) &&
                  (sVar10 = *(size_t *)((int)pvVar14 + 0x24),
                  pvVar14 = (void *)((int)pvVar14 + 0x18), sVar10 != 0));
          sVar10 = (uVar13 + 2) * 0x18;
        }
        iVar3 = EVP_DigestUpdate(pEVar8,d,sVar10);
        if (0 < iVar3) {
          iVar3 = EVP_DigestVerifyFinal(pEVar8,(uchar *)((int)pvVar2 + 0x148),0x100);
          EVP_MD_CTX_free(pEVar8);
          if (local_2c != (void *)0x0) goto LAB_0001278c;
          goto LAB_00012790;
        }
        puts(DAT_000128c0);
      }
      goto joined_r0x0001273c;
    }
    puts(DAT_000128a8);
    if (local_2c != (void *)0x0) {
LAB_0001278c:
      free(local_2c);
LAB_00012790:
      unlink(DAT_00012888);
      if (iVar3 == 1) {
        puts(DAT_000128ac);
        return 0;
      }
      goto LAB_0001274c;
    }
  }
  unlink(DAT_00012888);
LAB_0001274c:
  puts(DAT_000128a0);
  return 1;
}

