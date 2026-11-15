typedef struct {
  UINT8 Numlock;
  UINT8 SetupDisableTcgBlockSid;
  UINT8 FastBoot;
  UINT8 FbSata;
  UINT8 FbVga;
  UINT8 FbUsb;
  UINT8 FbPs2;
  UINT8 FbI2c;
  UINT8 FbRedirection;
  UINT8 FbNetworkStack;
  UINT8 FbNvme;
  UINT8 FbUfs;
  UINT16 FbDelayTime;
  UINT8 TpmEnable;
  UINT8 TpmOperation;
  UINT8 TpmEnaDisable;
  UINT8 TpmActDeact;
  UINT8 TpmOwnedUnowned;
  UINT8 TpmSupport;
  UINT8 TcgSupportEnabled;
  UINT8 TcmSupportEnabled;
  UINT8 TpmHrdW;
  UINT8 TpmAuthenticate;
  UINT8 SuppressTcg;
  UINT8 TpmError;
  UINT8 Tpm20Device;
  UINT8 Tcg2SpecVersion;
  UINT8 PlatformHierarchy;
  UINT8 StorageHierarchy;
  UINT8 EndorsementHierarchy;
  UINT8 InterfaceSel;
  UINT8 DeviceType;
  UINT8 PhRandomization;
  UINT8 Sha1Supported;
  UINT8 Sha256Supported;
  UINT8 Sha384Supported;
  UINT8 Sha512Supported;
  UINT8 SM3Supported;
  UINT8 Sha1;
  UINT8 Sha256;
  UINT8 Sha384;
  UINT8 Sha512;
  UINT8 SM3;
  UINT8 ForceTpmEnable;
  UINT8 PpiSpecVersion;
  UINT8 SaveSetupProfile;
  UINT8 LoadSetupProfile;
  UINT16 SaveSetupProfileName[14];
  UINT8 SaveSetupProfileToUsb;
  UINT8 LoadSetupProfileFromUsb;
  UINT8 LastSetupProfileName;
  UINT8 EmptySetupProfile;
  UINT8 AcpiAuto;
  UINT16 AcpiSleepState;
  UINT8 AcpiHibernate;
  UINT8 S3ResumeVideoRepost;
  UINT8 ForceToAcpi1;
  UINT8 RedfishEnable;
  UINT16 RedfishVersionBmc[16];
  UINT16 RedfishVersionBios[16];
  UINT8 AuthenticationMode;
  UINT16 RFServiceIpAddress[16];
  UINT16 RFServiceIpMask[16];
  UINT16 RFServiceIpPort;
  UINT32 RFServiceVlanId;
  UINT8 SmartSelfTest;
  UINT8 SpdSlot;
  UINT8 DimmPresent;
  UINT8 CuDimmPresent;
  UINT8 DimmExpoPresent;
  UINT8 ResetButton;
  UINT8 Ec1FanActiveEnabled;
  UINT8 Aux0FanSpecialControl;
  UINT8 Aux3FanSpecialControl;
  UINT8 NvLockSetupControl;
  UINT8 BaudRate[2];
  UINT8 DataBits[2];
  UINT8 Parity[2];
  UINT8 StopBits[2];
  UINT8 FlowControl[2];
  UINT8 ConsoleRedirectionEnable[2];
  UINT8 TerminalType[2];
  UINT8 VtUtf8[2];
  UINT8 RecorderMode[2];
  UINT8 Resolution[2];
  UINT8 LegacyOsResolution;
  UINT8 PuttyFunctionKeyPad[2];
  UINT8 RedirectionAfterBiosPost;
  UINT8 AcpiSpcrConsoleRedirectionEnable;
  UINT8 AcpiSpcrPort;
  UINT8 AcpiSpcrTerminalType;
  UINT8 AcpiSpcrBaudRate;
  UINT8 AcpiSpcrFlowControl;
  UINT8 AcpiSpcrSetupDummyVar;
  UINT8 DebuggerConsoleRedirectionEnable;
  UINT8 DebuggerTerminalType;
  UINT8 ComPortforLegacy;
  UINT8 VROC_IIO_PORT_1A;
  UINT8 VROC_IIO_PORT_2A;
  UINT8 VROC_IIO_PORT_3A;
  UINT8 VROC_IIO_PORT_3E;
  UINT8 VROC_IIO_PORT_4A;
  UINT8 VROC_PCH_PORT_04;
  UINT8 VROC_PCH_PORT_08;
  UINT8 VROC_PCH_PORT_12;
  UINT8 VROC_PCH_PORT_20;
  UINT8 VROC_PCH_PORT_24;
  UINT8 Above4gDecode;
  UINT8 ResizableBarSupport;
  UINT8 SriovSupport;
  UINT8 BmeDmaMitigation;
  UINT8 PciLatency;
  UINT8 VgaPallete;
  UINT8 PerrEnable;
  UINT8 SerrEnable;
  UINT8 PciXLatency;
  UINT8 RelaxedOrdering;
  UINT8 ExtTagField;
  UINT8 NoSnoop;
  UINT8 MaxPayload;
  UINT8 MaxReadRequest;
  UINT8 AspmMode;
  UINT8 ExtendedSynch;
  UINT8 LnkTrRetry;
  UINT16 LnkTrTimeout;
  UINT8 LnkDisable;
  UINT8 S3PciExpressScripts;
  UINT8 DontResetVcMapping;
  UINT8 ComplTimeOut;
  UINT8 AriFwd;
  UINT8 AtomOpReq;
  UINT8 AtomOpEgressBlk;
  UINT8 IDOReq;
  UINT8 IDOCompl;
  UINT8 LtrReport;
  UINT8 E2ETlpPrBlk;
  UINT8 LnkSpeed;
  UINT8 DeEmphasis;
  UINT8 ClockPm;
  UINT8 ComplSos;
  UINT8 HwAutoWidth;
  UINT8 HwAutoSpeed;
  UINT8 HotPlugEnable;
  UINT8 BusPadd;
  UINT8 IoPadd;
  UINT8 Mmio32Padd;
  UINT8 Mmio32PfPadd;
  UINT16 Mmio64Padd;
  UINT16 Mmio64PfPadd;
  UINT8 PchUsbPort[14];
  UINT8 OptimizedBoot;
  UINT8 FbPostTime;
  UINT8 PostReportSupport;
  UINT8 WaitForF1;
  UINT8 AiCharge;
  UINT8 StateAfterG3;
  UINT8 PowerupPCIE;
  UINT8 PowerupRTC;
  UINT8 PowerupRTCAlarmDate;
  UINT8 PowerupRTCHour;
  UINT8 PowerupRTCMinute;
  UINT8 PowerupRTCSecond;
  UINT8 PowerupKB;
  UINT8 PowerupMS;
  UINT8 PowerupUSB;
  UINT8 EUP;
  UINT8 CxEnable;
  UINT8 MonitorMWait;
  UINT8 C1AutoDemotion;
  UINT8 C1AutoUnDemotion;
  UINT8 ProcessorC1eEnable;
  UINT8 PackageCState;
  UINT8 ActiveCore[60];
  UINT8 CoreBOTable[60];
  UINT8 FusedMFC[60];
  UINT8 NumOfCores;
  UINT8 PwrPerfTuning;
  UINT8 AltEngPerfBIAS;
  UINT8 SAPMControl;
  UINT8 IntelPcieLanSupport;
  UINT8 MarvellLanSupport;
  UINT8 CxlDeviceSupport;
  UINT8 CHASSIS_INTRUDE_DETECT_Support;
  UINT8 CpuOvtLedSupport;
  UINT8 OnboardBmcEnable;
  UINT8 AsusNvmeNativeDriverSupport;
  UINT8 CheckKeyboardPresent;
  UINT8 G3BootMode;
  UINT8 AsusHddGptRecoveryPolicy;
  UINT8 AsusHddGptRecoveryUserAction;
  UINT8 CsmSupportAvailable;
  UINT8 CsmSupport;
  UINT8 PxeOpRom;
  UINT8 MassStorageOpRom;
  UINT8 VideoOpRom;
  UINT8 OldOpRom;
  UINT8 AsusArmouryCrateFlag;
  UINT8 HiiPublish;
  UINT8 MyAsusControl;
  UINT8 ImageRollbackSupport;
  UINT8 SlimSAS_2Switch;
  UINT8 PcieX16_1Switch;
  UINT8 PcieX16_2Switch;
  UINT8 PcieX16_3Switch;
  UINT8 PcieX16_4Switch;
  UINT8 PcieX16_4SwitchDetected;
  UINT8 PcieX16_5Switch;
  UINT8 PCIeX16_4_Gain_cha0[4];
  UINT8 PCIeX16_4_EQ_cha0[4];
  UINT8 PCIeX16_4_Gain_cha1[4];
  UINT8 PCIeX16_4_EQ_cha1[4];
  UINT8 PCIeX16_4_Gain_cha2[4];
  UINT8 PCIeX16_4_EQ_cha2[4];
  UINT8 PCIeX16_4_Gain_cha3[4];
  UINT8 PCIeX16_4_EQ_cha3[4];
} SETUP_DATA;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 HardDiskCount;
  UINT16 CDROMCount;
  UINT16 FloppyCount;
  UINT16 NetworkCount;
  UINT16 BevCount;
} LEGACY_DEV_LIST;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 SetupSaveState;
} SETUP_SAVE_STATE_INFO;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 GroupCount;
} LEGACY_DEV_INFO;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 DeviceCount;
} LEGACY_GROUP_INFO;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT8 Access;
} SYSTEM_ACCESS;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 BootCount;
} BOOT_MANAGER;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 BootCount;
} BOOT_NOW_COUNT;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Option;
} DEL_BOOT_OPTION;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Value;
} AMI_CALLBACK;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Value;
} TIMEOUT;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Value;
} BOOT_ORDER;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Value;
} LEGACY_DEV_ORDER;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Value;
} LANGUAGE;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Value;
} LANGUAGE_CODES;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Value;
} EFI_SHELL;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 PageCount;
} DYNAMIC_PAGE_COUNT;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 GroupCount;
} DYNAMIC_PAGE_GROUP_COUNT;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 DeviceCount;
} DYNAMIC_PAGE_DEVICE_COUNT;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 NonDeviceClassCount;
  UINT16 DiscDeviceClassCount;
  UINT16 VideoDeviceClassCount;
  UINT16 NetworkDeviceClassCount;
  UINT16 InputDeviceClassCount;
  UINT16 OnBoardDeviceClassCount;
  UINT16 OtherDeviceClassCount;
} DYNAMIC_PAGE_GROUP_CLASS_COUNT;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Value;
} OEMTSEVAR;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Enable;
} DRIVER_HEALTH_ENABLE;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 DrvHandleCount;
} DRIVER_HEALTH;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 DrvHealthCtrlCnt;
} DRIVER_HEALTH_CTRL_COUNT;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 DriverCount;
} DRIVER_MANAGER;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Value;
} DRIVER_ORDER;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Option;
} DEL_DRIVER_OPTION;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 ErrorCount;
  UINT16 ErrorFunction;
} ERROR_MANAGER;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Label[20];
  UINT16 FsCount;
  UINT16 SelFs;
  UINT16 Path[120];
} NEW_BOOT_OPTION;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Label[20];
  UINT16 FsCount;
  UINT16 SelFs;
  UINT16 DriverPath[120];
} NEW_DRIVER_OPTION;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Count;
} USER_DEFAULTS;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 Count;
  UINT16 Supported;
  UINT16 Enabled;
  UINT16 Locked;
  UINT16 Frozen;
  UINT16 UserPasswordStatus;
  UINT16 MasterPasswordStatus;
  UINT16 ShowMaster;
  UINT16 ShowUser;
  UINT16 IDEUserPassword[32];
  UINT16 IDEMasterPassword[32];
} IDE_SECURITY_CONFIG;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT16 UserPassword[20];
  UINT16 AdminPassword[20];
  UINT8 AMISilentBoot;
} AMITSESETUP;  // ADDED FROM GENERIC DEFINITIONS

typedef struct {
  UINT8 BmcSupport;
  UINT8 WaitForBmc;
  UINT16 TimeZone[6];
  UINT8 InterfaceTypeValid[8];
  UINT8 InterfaceType;
  UINT8 Frb2Enable;
  UINT8 Frb2Timeout;
  UINT8 Frb2TimeoutPolicy;
  UINT8 OsBootWdtEnable;
  UINT8 OsBootWdtTimeout;
  UINT8 OsBootWdtTimeoutPolicy;
  UINT8 SelLogging;
  UINT8 SelErase;
  UINT8 SelFull;
  UINT8 LogSelStatusCodes;
  UINT16 SelDelSupport;
  UINT8 BstErase;
  UINT8 BstLogFull;
  UINT8 RefInterval;
  UINT8 BmcLan1;
  UINT16 StationIp1[15];
  UINT16 Subnet1[15];
  UINT16 RouterIp1[15];
  UINT16 RouterMac1[17];
  UINT8 Ip6Support1;
  UINT8 PrefixLength1;
  UINT8 Ip6BmcLan1;
  UINT8 Ip6RouterLan1;
  UINT8 RouterPrefixLength1;
  UINT16 StaticIp6Lan1Router1Ip[40];
  UINT16 RouterPrefixValue1[40];
  UINT16 StaticIp6Lan1[40];
  UINT8 VlanSupportLan1;
  UINT8 VlanPriorityLan1;
  UINT16 VlanIdLan1;
  UINT16 AddBmcUserName[17];
  UINT16 AddBmcUserPassword[21];
  UINT16 DeleteBmcUserName[17];
  UINT16 ChangeUserSettingsBmcCurrentUserName[17];
  UINT16 ChangeUserSettingsBmcUserPassword[21];
  UINT8 AddBmcChannelNo;
  UINT8 AddBmcUserPrivilegeLimit;
  UINT8 AddBmcUserAccess;
  UINT8 AddBmcUserValidBmcUserCredentials;
  UINT8 AddBmcUserValidBmcUser;
  UINT8 AddBmcUserValidBmcLanChannel;
  UINT8 DeleteValidBmcUser;
  UINT8 ChangeUserSettingsBmcUserAccess;
  UINT8 ChangeUserSettingsBmcChannelNo;
  UINT8 ChangeUserSettingsBmcUserPrivilegeLimit;
  UINT8 ChangeUserSettingsValidBmcLanChannel;
  UINT8 ChangeUserSettingsValidPassword;
  UINT8 ChangeUserSettingsValidBmcUser;
  UINT8 ChangeUserSettingsValidBmcUserCredentials;
  UINT8 AddBmcUserMaximumPossibleUserPrivilegeLevel;
  UINT8 ChangeUserSettingsBmcUserMaximumPossibleUserPrivilegeLevel;
  UINT8 DriverType;
  UINT8 BmcInitPhase;
  UINT8 ViewSelLogFlag;
  UINT8 BmcLanLed;
  UINT8 BmcMsgLed;
  UINT8 BmcFanSrc;
} SERVER_MGMT_CONFIGURATION_DATA;  // ADDED FROM GENERIC DEFINITIONS

