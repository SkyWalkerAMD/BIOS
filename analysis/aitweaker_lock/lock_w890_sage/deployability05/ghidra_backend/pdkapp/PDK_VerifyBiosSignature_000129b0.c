
void PDK_VerifyBiosSignature(void)

{
  ushort uVar1;
  ushort uVar2;
  ulonglong uVar3;
  void *pvVar4;
  int iVar5;
  char *__s;
  RSA *pRVar6;
  BIGNUM *pBVar7;
  BIGNUM *pBVar8;
  EVP_PKEY *pEVar9;
  EVP_MD_CTX *pEVar10;
  EVP_MD *pEVar11;
  int iVar12;
  undefined4 uVar13;
  int iVar14;
  int iVar15;
  void *local_34;
  undefined4 local_30;
  EVP_PKEY_CTX *local_2c;
  undefined2 local_28;
  undefined1 local_26;
  int local_24;
  
  local_24 = **(int **)(DAT_00012d7c + 0x129c0 + DAT_00012d80);
  local_2c = (EVP_PKEY_CTX *)0x0;
  local_28 = *(undefined2 *)(DAT_00012d8c + 0x12a10);
  local_26 = *(undefined1 *)(DAT_00012d8c + 0x12a12);
  iVar5 = read_file_append(DAT_00012d88 + 0x129f4,DAT_00012d84 + 0x129e0,&local_34,&local_30);
  if (iVar5 < 0) {
    __s = (char *)(DAT_00012d90 + 0x12a28);
  }
  else {
    printf((char *)(DAT_00012da0 + 0x12a98),local_30);
    pvVar4 = local_34;
    pRVar6 = RSA_new();
    pBVar7 = BN_bin2bn((uchar *)((int)pvVar4 + 600),0x100,(BIGNUM *)0x0);
    pBVar8 = BN_bin2bn((uchar *)&local_28,3,(BIGNUM *)0x0);
    RSA_set0_key(pRVar6,pBVar7,pBVar8,0);
    pEVar9 = EVP_PKEY_new();
    EVP_PKEY_assign(pEVar9,6,pRVar6);
    pEVar10 = (EVP_MD_CTX *)EVP_MD_CTX_new();
    local_2c = EVP_PKEY_CTX_new(pEVar9,(ENGINE *)0x0);
    pEVar11 = EVP_sha256();
    iVar5 = EVP_DigestVerifyInit(pEVar10,&local_2c,pEVar11,(ENGINE *)0x0,pEVar9);
    if (iVar5 < 1) {
      __s = (char *)(DAT_00012da4 + 0x12b38);
    }
    else {
      iVar5 = EVP_PKEY_CTX_set_rsa_padding(local_2c,6);
      if (iVar5 < 1) {
LAB_00012b4c:
        __s = (char *)(DAT_00012da8 + 0x12b58);
      }
      else {
        printf((char *)(DAT_00012dac + 0x12b68),*(undefined4 *)((int)pvVar4 + 0x14));
        if ((*(uint *)((int)pvVar4 + 0x14) & 4) == 0) {
          uVar13 = 0x228;
          iVar5 = (int)pvVar4 + 0x20;
        }
        else {
          uVar13 = 0x100;
          iVar5 = (int)pvVar4 + 0x48;
        }
        iVar5 = EVP_DigestVerifyUpdate(pEVar10,iVar5,uVar13);
        if (iVar5 < 1) {
          __s = (char *)(DAT_00012db0 + 0x12b98);
        }
        else {
          iVar5 = EVP_DigestVerifyFinal(pEVar10,(uchar *)((int)pvVar4 + 0x358),0x100);
          EVP_MD_CTX_free(pEVar10);
          if (iVar5 != 1) {
            puts((char *)(DAT_00012dbc + 0x12c70));
            goto LAB_00012a2c;
          }
          puts((char *)(DAT_00012db4 + 0x12bc8));
          pRVar6 = RSA_new();
          pBVar7 = BN_bin2bn((uchar *)((int)pvVar4 + 0x48),0x100,(BIGNUM *)0x0);
          pBVar8 = BN_bin2bn((uchar *)&local_28,3,(BIGNUM *)0x0);
          RSA_set0_key(pRVar6,pBVar7,pBVar8,0);
          pEVar9 = EVP_PKEY_new();
          EVP_PKEY_assign(pEVar9,6,pRVar6);
          pEVar10 = (EVP_MD_CTX *)EVP_MD_CTX_new();
          local_2c = EVP_PKEY_CTX_new(pEVar9,(ENGINE *)0x0);
          pEVar11 = EVP_sha256();
          iVar5 = EVP_DigestVerifyInit(pEVar10,&local_2c,pEVar11,(ENGINE *)0x0,pEVar9);
          if (iVar5 < 1) {
            __s = (char *)(DAT_00012db8 + 0x12c64);
          }
          else {
            iVar5 = EVP_PKEY_CTX_set_rsa_padding(local_2c,6);
            if (iVar5 < 1) goto LAB_00012b4c;
            uVar1 = *(ushort *)((int)pvVar4 + 0x1e);
            iVar15 = 0;
            uVar2 = *(ushort *)((int)pvVar4 + 0x1c);
            iVar5 = (int)local_34 + (uint)uVar1;
            uVar3 = (ulonglong)DAT_00012dc0;
            while ((iVar15 < (int)(uint)(uVar3 * ((uint)uVar2 - (uint)uVar1) >> 0x24) &&
                   (iVar14 = iVar15 * 0x18 + iVar5, *(int *)(iVar14 + 0xc) != 0))) {
              if (((*(uint *)(iVar14 + 0x14) & 0x200) != 0) &&
                 (iVar12 = EVP_DigestVerifyUpdate
                                     (pEVar10,(int)local_34 +
                                              (uint)*(ushort *)((int)pvVar4 + 0x1c) +
                                              *(int *)(iVar14 + 8)), iVar12 < 1)) {
                printf((char *)(DAT_00012dc8 + 0x12d34),*(undefined4 *)(iVar14 + 8),
                       *(undefined4 *)(iVar14 + 0xc));
                goto LAB_00012a28;
              }
              iVar15 = iVar15 + 1;
            }
            iVar5 = EVP_DigestVerifyUpdate(pEVar10,iVar5,iVar15 * 0x18 + 0x18);
            if (0 < iVar5) {
              iVar5 = EVP_DigestVerifyFinal(pEVar10,(uchar *)((int)pvVar4 + 0x148),0x100);
              EVP_MD_CTX_free(pEVar10);
              goto LAB_00012a2c;
            }
            __s = (char *)(DAT_00012dc4 + 0x12cf0);
          }
        }
      }
    }
  }
  puts(__s);
LAB_00012a28:
  iVar5 = -1;
LAB_00012a2c:
  if (local_34 != (void *)0x0) {
    free(local_34);
  }
  unlink((char *)(DAT_00012d94 + 0x12a48));
  if (iVar5 != 1) {
    puts((char *)(DAT_00012dcc + 0x12d6c));
  }
  else {
    puts((char *)(DAT_00012d98 + 0x12a5c));
  }
  if (local_24 == **(int **)(DAT_00012d9c + 0x12a70 + DAT_00012d80)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(iVar5 != 1);
}

