
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

