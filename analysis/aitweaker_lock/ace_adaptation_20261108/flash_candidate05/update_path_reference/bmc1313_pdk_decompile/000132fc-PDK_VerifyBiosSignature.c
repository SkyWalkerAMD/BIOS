
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
  void *pvVar13;
  uint uVar14;
  void *d;
  undefined2 local_30;
  undefined1 local_2e;
  void *local_2c;
  undefined4 local_28;
  EVP_PKEY_CTX *local_24 [2];
  
  local_30 = (undefined2)*(undefined4 *)(DAT_000137c4 + 0x14);
  local_2e = (undefined1)((uint)*(undefined4 *)(DAT_000137c4 + 0x14) >> 0x10);
  local_24[0] = (EVP_PKEY_CTX *)0x0;
  iVar3 = read_file_append(DAT_000137cc,DAT_000137c8,&local_2c,&local_28);
  if (iVar3 < 0) {
    puts(DAT_000137ec);
joined_r0x00013650:
    if (local_2c != (void *)0x0) {
      free(local_2c);
    }
  }
  else {
    printf(DAT_000137d0,local_28);
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
      puts(DAT_000137f8);
      goto joined_r0x00013650;
    }
    iVar3 = RSA_pkey_ctx_ctrl(local_24[0],0xffffffff,DAT_000137d4,6,0);
    if (iVar3 < 1) {
      puts(DAT_000137f4);
      goto joined_r0x00013650;
    }
    printf(DAT_000137d8,*(undefined4 *)((int)pvVar2 + 0x14));
    if ((*(byte *)((int)pvVar2 + 0x14) & 4) == 0) {
      iVar3 = EVP_DigestUpdate(pEVar8,(void *)((int)pvVar2 + 0x20),0x228);
    }
    else {
      iVar3 = EVP_DigestUpdate(pEVar8,(void *)((int)pvVar2 + 0x48),0x100);
    }
    if (iVar3 < 1) {
      puts(DAT_000137f0);
      goto joined_r0x00013650;
    }
    iVar3 = EVP_DigestVerifyFinal(pEVar8,(uchar *)((int)pvVar2 + 0x358),0x100);
    EVP_MD_CTX_free(pEVar8);
    if (iVar3 == 1) {
      puts(DAT_000137dc);
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
        puts(DAT_00013804);
      }
      else {
        iVar3 = RSA_pkey_ctx_ctrl(local_24[0],0xffffffff,DAT_000137d4,6,0);
        if (iVar3 < 1) {
          puts(DAT_000137f4);
        }
        else {
          uVar11 = (uint)*(ushort *)((int)pvVar2 + 0x1c) - (uint)*(ushort *)((int)pvVar2 + 0x1e);
          uVar1 = (ulonglong)DAT_000137e0;
          d = (void *)((int)local_2c + (uint)*(ushort *)((int)pvVar2 + 0x1e));
          if ((uVar11 < 0x18) ||
             (sVar10 = *(size_t *)((int)d + 0xc), pvVar13 = d, uVar12 = 0, sVar10 == 0)) {
            sVar10 = 0x18;
          }
          else {
            do {
              uVar14 = uVar12;
              if (((*(byte *)((int)pvVar13 + 0x15) & 2) != 0) &&
                 (iVar3 = EVP_DigestUpdate(pEVar8,(void *)((int)local_2c +
                                                          (uint)*(ushort *)((int)pvVar2 + 0x1c) +
                                                          *(int *)((int)pvVar13 + 8)),sVar10),
                 iVar3 < 1)) {
                printf(DAT_000137e4,*(undefined4 *)((int)pvVar13 + 8),
                       *(undefined4 *)((int)pvVar13 + 0xc));
                goto joined_r0x00013650;
              }
              uVar12 = uVar14 + 1;
            } while (((uint)(uVar1 * uVar11 >> 0x24) != uVar12) &&
                    (sVar10 = *(size_t *)((int)pvVar13 + 0x24),
                    pvVar13 = (void *)((int)pvVar13 + 0x18), sVar10 != 0));
            sVar10 = (uVar14 + 2) * 0x18;
          }
          iVar3 = EVP_DigestUpdate(pEVar8,d,sVar10);
          if (0 < iVar3) {
            iVar3 = EVP_DigestVerifyFinal(pEVar8,(uchar *)((int)pvVar2 + 0x148),0x100);
            EVP_MD_CTX_free(pEVar8);
            if (local_2c != (void *)0x0) goto LAB_00013700;
            goto LAB_00013704;
          }
          puts(DAT_00013808);
        }
      }
      goto joined_r0x00013650;
    }
    puts(DAT_000137fc);
    if (local_2c != (void *)0x0) {
LAB_00013700:
      free(local_2c);
LAB_00013704:
      unlink(DAT_000137cc);
      if (iVar3 == 1) {
        puts(DAT_00013800);
        return 0;
      }
      goto LAB_00013660;
    }
  }
  unlink(DAT_000137cc);
LAB_00013660:
  puts(DAT_000137e8);
  return 1;
}

