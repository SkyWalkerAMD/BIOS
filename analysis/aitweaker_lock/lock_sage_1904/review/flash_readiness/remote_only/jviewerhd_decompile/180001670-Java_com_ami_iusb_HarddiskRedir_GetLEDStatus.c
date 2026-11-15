
undefined2 Java_com_ami_iusb_HarddiskRedir_GetLEDStatus(void)

{
  SHORT SVar1;
  SHORT SVar2;
  ushort uVar3;
  
                    /* 0x1670  1  Java_com_ami_iusb_HarddiskRedir_GetLEDStatus */
  SVar1 = GetKeyState(0x90);
  SVar2 = GetKeyState(0x14);
  uVar3 = GetKeyState(0x91);
  return CONCAT11((char)((uVar3 & 0xff01) >> 8),
                  (char)(uVar3 & 0xff01) << 2 | (byte)SVar1 & 1 | ((byte)SVar2 & 1) * '\x02');
}

