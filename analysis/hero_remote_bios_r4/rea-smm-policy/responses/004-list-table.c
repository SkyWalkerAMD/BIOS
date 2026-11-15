/* 0x3c3c resolves {'status': 'resolved', 'address': '0x3c3c', 'name': 'FUN_00003c3c'} */

ulonglong FUN_00003c3c(longlong *param_1,undefined8 param_2,undefined8 param_3)

{
  longlong *plVar1;
  longlong lVar2;
  longlong *in_RAX;
  undefined8 uVar3;
  ulonglong uVar4;
  
  if (param_1 != (longlong *)0x0) {
    uVar4 = 0;
    lVar2 = *param_1;
    plVar1 = param_1;
    while (lVar2 != 0) {
      uVar3 = (*(code *)*plVar1)(param_2,param_3);
      if ((char)uVar3 != '\0') {
        return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
      }
      uVar4 = (ulonglong)((int)uVar4 + 1);
      plVar1 = param_1 + uVar4;
      in_RAX = plVar1;
      lVar2 = *plVar1;
    }
  }
  return (ulonglong)in_RAX & 0xffffffffffffff00;
}


/* 0x3b40 resolves {'status': 'resolved', 'address': '0x3a10', 'name': 'FUN_00003a10'} */

char * FUN_00003a10(short *param_1,undefined8 param_2,ulonglong param_3,char *param_4)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  char *pcVar3;
  longlong lVar4;
  char *pcVar5;
  char cVar6;
  wchar_t *pwVar7;
  char *pcVar8;
  char cVar9;
  wchar_t wVar10;
  char *pcVar11;
  char *pcVar12;
  char *pcVar13;
  char *pcVar14;
  ulonglong local_res8;
  
  pwVar2 = u_Timeout_00012318;
  pcVar8 = (char *)0x0;
  wVar10 = *param_1;
  wVar1 = wVar10;
  pwVar7 = param_1;
  while ((wVar1 != L'\0' && (wVar1 == *pwVar2))) {
    pwVar7 = pwVar7 + 1;
    pwVar2 = pwVar2 + 1;
    wVar1 = *pwVar7;
  }
  if (*pwVar7 == *pwVar2) {
    return (char *)(-(ulonglong)(param_3 != 2) & 0x8000000000000002);
  }
  pwVar2 = u_PlatformLang_00012350;
  while ((wVar10 != L'\0' && (wVar10 == *pwVar2))) {
    param_1 = param_1 + 1;
    pwVar2 = pwVar2 + 1;
    wVar10 = *param_1;
  }
  if (*param_1 != *pwVar2) {
    return (char *)0x0;
  }
  local_res8 = 0;
  if ((2 < param_3) && (param_4[param_3 - 1] == '\0')) {
    cVar6 = *param_4;
    pcVar11 = pcVar8;
    cVar9 = cVar6;
    while (cVar9 != '\0') {
      pcVar11 = pcVar11 + 1;
      cVar9 = pcVar11[(longlong)param_4];
    }
    pcVar5 = param_4;
    if ((char *)(param_3 - 1) == pcVar11) {
      while (pcVar11 = pcVar8, cVar6 != '\0') {
        pcVar12 = &DAT_000126f0;
        pcVar3 = pcVar5;
        if (cVar6 == ';') {
          do {
            if (cVar6 == '\0') break;
            pcVar3 = pcVar3 + 1;
            pcVar12 = pcVar12 + 1;
            cVar6 = *pcVar3;
          } while (cVar6 == *pcVar12);
          pcVar11 = pcVar5;
          if (*pcVar12 == '\0') break;
        }
        if (*pcVar3 == '\0') goto LAB_00003b2b;
        cVar6 = pcVar5[1];
        pcVar5 = pcVar5 + 1;
      }
      if (pcVar11 == (char *)0x0) {
LAB_00003b2b:
        lVar4 = FUN_00005a58((ushort *)u_PlatformLangCodes_00012328,&DAT_00011020,(uint *)0x0,
                             &local_res8,(undefined8 *)0x0);
        if (lVar4 == -0x7ffffffffffffffb) {
          if (local_res8 < param_3) {
            return (char *)0x8000000000000002;
          }
          pcVar11 = (char *)FUN_00001d24(local_res8);
          if (pcVar11 != (char *)0x0) {
            pcVar5 = (char *)FUN_00005a58((ushort *)u_PlatformLangCodes_00012328,&DAT_00011020,
                                          (uint *)0x0,&local_res8,(undefined8 *)pcVar11);
            if (-1 < (longlong)pcVar5) {
              pcVar3 = pcVar11;
              if (*param_4 != '\0') {
                cVar9 = *pcVar11;
                pcVar12 = pcVar11;
                while (pcVar3 = pcVar8, cVar9 != '\0') {
                  pcVar13 = pcVar12;
                  pcVar14 = param_4;
                  if (cVar9 == *param_4) {
                    do {
                      if (cVar9 == '\0') break;
                      pcVar13 = pcVar13 + 1;
                      pcVar14 = pcVar14 + 1;
                      cVar9 = *pcVar13;
                    } while (cVar9 == *pcVar14);
                  }
                  pcVar3 = pcVar12;
                  if (*pcVar14 == '\0') break;
                  if (*pcVar13 == '\0') goto LAB_00003bfd;
                  pcVar12 = pcVar12 + 1;
                  cVar9 = *pcVar12;
                }
              }
              if ((pcVar3 == (char *)0x0) ||
                 ((pcVar8 = pcVar5, pcVar3[param_3 - 1] != '\0' && (pcVar3[param_3 - 1] != ';')))) {
LAB_00003bfd:
                pcVar8 = (char *)0x8000000000000002;
              }
            }
            FUN_00001d7c((longlong)pcVar11);
            return pcVar8;
          }
        }
        return (char *)0x0;
      }
    }
  }
  return (char *)0x8000000000000002;
}


/* 0x9168 resolves {'status': 'unknown', 'error': {'code': 'invalid_request', 'category': 'invalid_input', 'message': 'Analysis input is invalid. Check the arguments and try again.', 'retryable': False, 'remediation': {'action': 'Read the declared input schema or CLI usage for procedure_address; if using MCP and the catalog may be stale, call tools/list. Correct the listed fields, then retry. Do not repeat the unchanged call.'}, 'recovery': {'kind': 'inspect_input_contract', 'operation': 'procedure_address'}, 'details': {'operation': 'procedure_address', 'issues': [{'path': [], 'reason': 'invalid_value', 'message': 'No procedure exists at the requested address: 0x9168; Ghidra image base: 0x0. Choose an observed analysis address. CLI: rea search <path> . --kind procedures --mode regex --provider ghidra --json; MCP: list_procedures. Inspect the loaded base and source mappings with CLI rea analyze <path> --provider ghidra --json and rea inspect-native-load-image <path> --provider ghidra --json, or MCP binary_overview and inspect_native_load_image. Repeat the original target options. For decompile, select source coordinates explicitly with --file-offset=0x... or MCP procedure file-offset:0x....'}], 'diagnostics': {'target_path': 'F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\reference\\447A1B58-8F3E-4658-ABAA-9E7B2280B90A.efi', 'target_sha256': '253eee0b0366dc5d7df33b18e9a298364decdac68923e8773031561e08d30c02', 'target_admission': {'source': {'requestedPath': 'F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\reference\\447A1B58-8F3E-4658-ABAA-9E7B2280B90A.efi', 'finalPath': '\\\\?\\F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\reference\\447A1B58-8F3E-4658-ABAA-9E7B2280B90A.efi', 'filesystem': 'NTFS', 'volumeSerial': '15d61abc4fbeb408', 'fileId': 'dc5e3900000006000000000000000000', 'size': 96768, 'directory': False}, 'snapshot': {'requestedPath': 'F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\target-253eee0b0366.efi', 'finalPath': '\\\\?\\F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\target-253eee0b0366.efi', 'filesystem': 'NTFS', 'volumeSerial': '15d61abc4fbeb408', 'fileId': '4e613900000001000000000000000000', 'size': 96768, 'directory': False}}, 'transport': 'authenticated-loopback-tcp', 'provider_version': '12.1.4', 'profile_digest': '8ca9ba8ec17cc87817522f08f546e9a6735e87524b94ac1cbd04b6bc69518843', 'run_id': '441f60bd-1820-491f-91f3-e8cfec14d663', 'runtime_root': 'F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d', 'endpoint_path': 'F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\bridge-endpoint.json', 'project_root': 'F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\project', 'ghidra_log_path': 'F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\ghidra.log', 'script_log_path': 'F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\script.log', 'process_id': 15904, 'launch_support': [{'mode': '-envvars', 'stderr': 'NOTE: Picked up JDK_JAVA_OPTIONS: "-Duser.home=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\home" "-Djava.io.tmpdir=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\tmp" "-XX:-UsePerfData"\r\nPicked up JAVA_TOOL_OPTIONS: \nPicked up _JAVA_OPTIONS: \n', 'stderr_bytes': 412, 'stderr_truncated': False}, {'mode': '-vmargs', 'stderr': 'NOTE: Picked up JDK_JAVA_OPTIONS: "-Duser.home=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\home" "-Djava.io.tmpdir=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\tmp" "-XX:-UsePerfData"\r\nPicked up JAVA_TOOL_OPTIONS: \nPicked up _JAVA_OPTIONS: \n', 'stderr_bytes': 412, 'stderr_truncated': False}], 'exit_code': None, 'exit_signal': None, 'stop_requested': False, 'diagnostic_truncated': False, 'output_incomplete': False, 'stdout': {'text': 'INFO  Using log config file: jar:file:/F:/OpenAI/Codex/project/BIOS/tools/rea-hero-12.1.4/ghidra_12.1.4_PUBLIC/Ghidra/Framework/Generic/lib/Generic.jar!/generic.log4j.xml (LoggingInitialization)  \r\nINFO  Using log file: F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\ghidra.log (LoggingInitialization)  \r\nINFO  Loading user preferences: F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\config\\scka7-ghidra\\ghidra_12.1.4_PUBLIC\\preferences (Preferences)  \r\nINFO  Searching for classes... (ClassSearcher)  \r\nINFO  Class search complete (643 ms) (ClassSearcher)  \r\nINFO  Initializing SSL Context (DefaultSSLContextInitializer)  \r\nINFO  Initializing Random Number Generator... (SecureRandomFactory)  \r\nINFO  Random Number Generator initialization complete: SHA1PRNG (SecureRandomFactory)  \r\nINFO  Trust manager disabled, cacerts have not been set (DefaultTrustManagerFactory)  \r\nINFO  Starting cache cleanup: F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\cache\\scka7-ghidra\\fscache2 (FileCacheMaintenanceDaemon)  \r\nINFO  Finished cache cleanup, estimated storage used: 0 (FileCacheMaintenanceDaemon)  \r\nINFO  Headless startup complete (1621 ms) (AnalyzeHeadless)  \r\nINFO  Class searcher loaded 59 extension points (20 false positives) (ClassSearcher)  \r\nINFO  HEADLESS Script Paths:\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\BytePatterns\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\FileFormats\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\GnuDemangler\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-runtime\\node_modules\\rea-agents\\bridge\\ghidra\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Debug\\Debugger-rmi-trace\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Debug\\Debugger\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Processors\\JVM\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\Decompiler\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\VersionTracking\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\BSim\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\MicrosoftCodeAnalyzer\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Processors\\DATA\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\SwiftDemangler\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\SystemEmulation\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Processors\\Atmel\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\DecompilerDependent\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Processors\\8051\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\Base\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\WildcardAssembler\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Processors\\PIC\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\PDB\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\PyGhidra\\ghidra_scripts\n    F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\FunctionID\\ghidra_scripts (HeadlessAnalyzer)  \r\nINFO  HEADLESS: execution starts (HeadlessAnalyzer)  \r\nINFO  Creating temporary project: F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\project\\rea-project (HeadlessAnalyzer)  \r\nINFO  Creating project: F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\project\\rea-project (DefaultProject)  \r\nINFO  REPORT: Processing input files:  (HeadlessAnalyzer)  \r\nINFO       project: F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\project\\rea-project (HeadlessAnalyzer)  \r\nINFO  IMPORTING: file:///F:/OpenAI/Codex/project/BIOS/analysis/hero_remote_bios_r4/rea-smm-policy/runtime-temp/rea-ghidra-a80c4e88cc08f214c57131868c378e9d/target-253eee0b0366.efi (HeadlessAnalyzer)  \r\nINFO  Using Loader: Portable Executable (PE) (ProgramLoader)  \r\nINFO  Using Language/Compiler: x86:LE:64:default:windows (ProgramLoader)  \r\nINFO  Using Library Search Path: [., C:\\WINDOWS\\SysWOW64, D:\\JAVA\\jdk-27\\bin, C:\\WINDOWS\\Sun\\Java\\bin, C:\\WINDOWS\\system32, C:\\WINDOWS, C:\\Users\\scka7\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\native\\powershell, C:\\Users\\scka7\\.codex\\tmp\\arg0-windows\\codex-arg0pt2n8T, C:\\Users\\scka7\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\native\\libheif\\libheif\\bin, C:\\Users\\scka7\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\native\\jxrlib\\jxrlib\\bin, C:\\Users\\scka7\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\native\\poppler\\Library\\bin, C:\\Users\\scka7\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\bin\\override, D:\\SecureCRT\\, C:\\WINDOWS\\System32\\Wbem, C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\, C:\\WINDOWS\\System32\\OpenSSH\\, C:\\Program Files (x86)\\NVIDIA Corporation\\PhysX\\Common, C:\\Program Files\\dotnet\\, D:\\Git\\cmd, C:\\Program Files\\GitHub CLI\\, D:\\Node\\, D:\\NVIDIA\\TensorRT-11.2.1.2\\bin, D:\\NVIDIA\\CUDA_13.3.1\\bin, C:\\Users\\scka7\\AppData\\Local\\Microsoft\\WindowsApps, C:\\Users\\scka7\\AppData\\Roaming\\npm, D:\\Microsoft VS Code\\bin, C:\\Users\\scka7\\AppData\\Local\\Microsoft\\WinGet\\Links, D:\\OpenSSL-Win64\\bin, C:\\Users\\scka7\\AppData\\Local\\Python\\bin, C:\\Users\\scka7\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\bin\\fallback, C:\\Users\\scka7\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\node\\bin, C:\\Users\\scka7\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\native\\git\\cmd, C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.1027.3384.0_x64__2p2nqsd0c76g0\\app\\resources] (ProgramLoader)  \r\nINFO  Additional info:\nLoading file:///F:/OpenAI/Codex/project/BIOS/analysis/hero_remote_bios_r4/rea-smm-policy/runtime-temp/rea-ghidra-a80c4e88cc08f214c57131868c378e9d/target-253eee0b0366.efi?MD5=88f30aa2836dbcb530e5d29fca30d2b2...\n------------------------------------------------\n\n (ProgramLoader)  \r\nINFO  IMPORTING: Loaded 0 additional files (HeadlessAnalyzer)  \r\nINFO  REPORT: Execute script: F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-runtime\\node_modules\\rea-agents\\bridge\\ghidra\\ReaGhidraApplySeeds.java \'F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\seeds\\seeds.tsv\'  (HeadlessAnalyzer)  \r\nINFO  SCRIPT: F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-runtime\\node_modules\\rea-agents\\bridge\\ghidra\\ReaGhidraApplySeeds.java (HeadlessAnalyzer)  \r\nINFO  ReaGhidraApplySeeds.java> REA seeds applied: {"format":"rea-ghidra-seeds-v1","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","entries":0,"function_created":0,"function_existing":0,"function_failed":0,"code_decoded":0,"code_failed":0,"label_applied":0,"label_failed":0,"unmapped":0} (GhidraScript)  \r\nINFO  ANALYZING all memory and code: file:///F:/OpenAI/Codex/project/BIOS/analysis/hero_remote_bios_r4/rea-smm-policy/runtime-temp/rea-ghidra-a80c4e88cc08f214c57131868c378e9d/target-253eee0b0366.efi (HeadlessAnalyzer)  \r\nWARN  Ignoring leading \'_\' chars on no-return name \'___raise_securityfailure\' specified in file: F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\Base\\data\\PEFunctionsThatDoNotReturn (NoReturnFunctionAnalyzer)  \r\nWARN  Ignoring leading \'_\' chars on no-return name \'___report_rangecheckfailure\' specified in file: F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-hero-12.1.4\\ghidra_12.1.4_PUBLIC\\Ghidra\\Features\\Base\\data\\PEFunctionsThatDoNotReturn (NoReturnFunctionAnalyzer)  \r\nINFO  Skipping PDB processing: missing PDB information in program metadata (PdbUniversalAnalyzer)  \r\nINFO  Packed database cache: F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\cache\\scka7-ghidra\\packed-db-cache (PackedDatabaseCache)  \r\nINFO  Applied data type archive: windows_vs12_64 (ApplyDataArchiveAnalyzer)  \r\nINFO  -----------------------------------------------------\n    ASCII Strings                              0.219 secs\n    Apply Data Archives                        0.428 secs\n    Call Convention ID                         0.001 secs\n    Call-Fixup Installer                       0.003 secs\n    Create Address Tables                      0.011 secs\n    Create Address Tables - One Time           0.020 secs\n    Create Function                            0.066 secs\n    Data Reference                             0.025 secs\n    Decompiler Parameter ID                    2.818 secs\n    Decompiler Switch Analysis                 1.255 secs\n    Demangler Microsoft                        0.003 secs\n    Disassemble                                0.033 secs\n    Disassemble Entry Points                   0.331 secs\n    Embedded Media                             0.011 secs\n    External Entry References                  0.000 secs\n    Function ID                                0.127 secs\n    Function Start Search                      0.004 secs\n    Non-Returning Functions - Discovered       0.016 secs\n    Non-Returning Functions - Known            0.002 secs\n    PDB Universal                              0.001 secs\n    Reference                                  0.049 secs\n    Shared Return Calls                        0.038 secs\n    Stack                                      0.380 secs\n    Subroutine References                      0.052 secs\n    Subroutine References - One Time           0.001 secs\n    WindowsResourceReference                   1.471 secs\n    x86 Constant Reference Analyzer            0.510 secs\n-----------------------------------------------------\n     Total Time   7 secs\n-----------------------------------------------------\n (AutoAnalysisManager)  \r\nINFO  REPORT: Analysis succeeded for file: file:///F:/OpenAI/Codex/project/BIOS/analysis/hero_remote_bios_r4/rea-smm-policy/runtime-temp/rea-ghidra-a80c4e88cc08f214c57131868c378e9d/target-253eee0b0366.efi (HeadlessAnalyzer)  \r\nINFO  REPORT: Execute script: F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-runtime\\node_modules\\rea-agents\\bridge\\ghidra\\ReaGhidraBridge.java \'F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\session.json\'  (HeadlessAnalyzer)  \r\nINFO  SCRIPT: F:\\OpenAI\\Codex\\project\\BIOS\\tools\\rea-runtime\\node_modules\\rea-agents\\bridge\\ghidra\\ReaGhidraBridge.java (HeadlessAnalyzer)  \r\n', 'bytes': 11605, 'retained_bytes': 11605}, 'stderr': {'text': 'NOTE: Picked up JDK_JAVA_OPTIONS: "-Duser.home=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\home" "-Djava.io.tmpdir=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\tmp" "-XX:-UsePerfData"\r\nPicked up JAVA_TOOL_OPTIONS: \nPicked up _JAVA_OPTIONS: \nNOTE: Picked up JDK_JAVA_OPTIONS: "-Duser.home=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\home" "-Djava.io.tmpdir=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\tmp" "-XX:-UsePerfData"\r\nPicked up JAVA_TOOL_OPTIONS: \nPicked up _JAVA_OPTIONS: \nNOTE: Picked up JDK_JAVA_OPTIONS: "-Duser.home=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\home" "-Djava.io.tmpdir=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\tmp" "-XX:-UsePerfData"\r\nPicked up JAVA_TOOL_OPTIONS: \nPicked up _JAVA_OPTIONS: \nNOTE: Picked up JDK_JAVA_OPTIONS: "-Duser.home=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\home" "-Djava.io.tmpdir=F:\\OpenAI\\Codex\\project\\BIOS\\analysis\\hero_remote_bios_r4\\rea-smm-policy\\runtime-temp\\rea-ghidra-a80c4e88cc08f214c57131868c378e9d\\tmp" "-XX:-UsePerfData"\r\nPicked up JAVA_TOOL_OPTIONS: \nPicked up _JAVA_OPTIONS: \nWARNING: Final field name in class ghidra.util.charset.CharsetInfo has been mutated reflectively by class com.google.gson.internal.bind.ReflectiveTypeAdapterFactory$2 in unnamed module @54e1c68b (file:/F:/OpenAI/Codex/project/BIOS/tools/rea-hero-12.1.4/ghidra_12.1.4_PUBLIC/Ghidra/Framework/Generic/lib/gson-2.13.2.jar)\nWARNING: Use --enable-final-field-mutation=ALL-UNNAMED to avoid a warning\nWARNING: Mutating final fields will be blocked in a future release unless final field mutation is enabled\nWARNING: A terminally deprecated method in sun.misc.Unsafe has been called\nWARNING: sun.misc.Unsafe::staticFieldOffset has been called by org.apache.felix.framework.util.SecureAction (file:/F:/OpenAI/Codex/project/BIOS/tools/rea-hero-12.1.4/ghidra_12.1.4_PUBLIC/Ghidra/Features/Base/lib/org.apache.felix.framework-7.0.5.jar)\nWARNING: Please consider reporting this to the maintainers of class org.apache.felix.framework.util.SecureAction\nWARNING: sun.misc.Unsafe::staticFieldOffset will be removed in a future release\r\n', 'bytes': 2667, 'retained_bytes': 2667}, 'failure_output': {'stdout': {'text': '', 'bytes': 0, 'retained_bytes': 0}, 'stderr': {'text': '', 'bytes': 0, 'retained_bytes': 0}, 'complete': True, 'observed_oome': []}, 'failure_cause': {'name': 'GhidraRemoteError', 'message': 'No procedure exists at the requested address: 0x9168; Ghidra image base: 0x0. Choose an observed analysis address. CLI: rea search <path> . --kind procedures --mode regex --provider ghidra --json; MCP: list_procedures. Inspect the loaded base and source mappings with CLI rea analyze <path> --provider ghidra --json and rea inspect-native-load-image <path> --provider ghidra --json, or MCP binary_overview and inspect_native_load_image. Repeat the original target options. For decompile, select source coordinates explicitly with --file-offset=0x... or MCP procedure file-offset:0x....', 'code': 'not_found'}, 'failure_kind': 'remote', 'failure_message': 'No procedure exists at the requested address: 0x9168; Ghidra image base: 0x0. Choose an observed analysis address. CLI: rea search <path> . --kind procedures --mode regex --provider ghidra --json; MCP: list_procedures. Inspect the loaded base and source mappings with CLI rea analyze <path> --provider ghidra --json and rea inspect-native-load-image <path> --provider ghidra --json, or MCP binary_overview and inspect_native_load_image. Repeat the original target options. For decompile, select source coordinates explicitly with --file-offset=0x... or MCP procedure file-offset:0x....', 'remote_code': 'not_found', 'remote_message': 'No procedure exists at the requested address: 0x9168; Ghidra image base: 0x0. Choose an observed analysis address. CLI: rea search <path> . --kind procedures --mode regex --provider ghidra --json; MCP: list_procedures. Inspect the loaded base and source mappings with CLI rea analyze <path> --provider ghidra --json and rea inspect-native-load-image <path> --provider ghidra --json, or MCP binary_overview and inspect_native_load_image. Repeat the original target options. For decompile, select source coordinates explicitly with --file-offset=0x... or MCP procedure file-offset:0x....'}}}} */

ulonglong FUN_000094b8(char *param_1,ulonglong param_2,ulonglong param_3,byte *param_4,
                      ulonglong *param_5)

{
  ushort uVar1;
  bool bVar2;
  ulonglong uVar3;
  char cVar4;
  int iVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  longlong lVar8;
  char *pcVar9;
  ulonglong uVar10;
  longlong lVar11;
  longlong lVar12;
  longlong lVar13;
  ulonglong uVar14;
  char *pcVar15;
  uint uVar16;
  ulonglong *puVar17;
  uint uVar18;
  ulonglong *puVar19;
  byte *pbVar20;
  ulonglong uVar21;
  ulonglong uVar22;
  bool bVar23;
  ulonglong local_res18;
  byte *local_res20;
  char *local_d8;
  ulonglong local_d0;
  ulonglong local_c0;
  ulonglong local_b8;
  ulonglong *local_b0;
  ulonglong local_a8;
  ulonglong local_a0;
  ulonglong local_98;
  longlong local_90;
  ulonglong local_88;
  ulonglong local_80;
  char *local_78;
  undefined8 local_70;
  ulonglong local_48;
  
  puVar17 = (ulonglong *)0x0;
  local_b0 = (ulonglong *)0x0;
  if (param_2 == 0) {
    uVar22 = (ulonglong)((uint)param_3 & 0x2000);
    if ((param_3 & 0x2000) == 0) goto LAB_00009517;
  }
  else {
    uVar22 = (ulonglong)((uint)param_3 & 0x2000);
    if (((param_3 & 0x2000) == 0) && (param_1 == (char *)0x0)) {
      return 0;
    }
  }
  if (param_4 == (byte *)0x0) {
    return 0;
  }
LAB_00009517:
  uVar6 = 1;
  if ((param_3 & 0x40) == 0) {
    uVar14 = uVar6;
    if (1000000 < param_2) {
      return 0;
    }
  }
  else {
    if (1000000 < param_2) {
      return 0;
    }
    uVar14 = 2;
  }
  if ((param_3 >> 8 & 1) == 0) {
    uVar21 = FUN_00009388((char *)param_4);
    if (1000000 < uVar21) {
      return 0;
    }
    local_98 = 0xff;
  }
  else {
    uVar6 = FUN_000092b4((short *)param_4,0xf4241);
    if (1000000 < uVar6) {
      return 0;
    }
    puVar17 = (ulonglong *)0x0;
    local_98 = 0xffff;
    uVar6 = 2;
  }
  local_80 = uVar6;
  if (uVar22 == 0) {
    if (param_2 == 0) {
      return 0;
    }
  }
  else {
    param_1 = (char *)((ulonglong)param_1 & -(ulonglong)(param_2 != 0));
  }
  local_78 = (char *)0x0;
  local_d0 = 0;
  local_d8 = (char *)0x0;
  if (param_1 != (char *)0x0) {
    local_78 = param_1;
    local_d8 = param_1 + (param_2 - 1) * uVar14;
  }
  if (uVar6 == 1) {
    iVar5 = 0;
  }
  else {
    iVar5 = (int)(char)param_4[1] << 8;
  }
  local_a8 = ((ulonglong)*param_4 | (longlong)iVar5) & local_98;
  local_res20 = param_4;
LAB_0000a1b8:
  uVar22 = 1;
  if ((local_a8 != 0) && ((param_1 == (char *)0x0 || (param_1 < local_d8)))) {
    local_a0 = 0;
    uVar6 = 0;
    local_90 = 0;
    cVar4 = '\0';
    uVar21 = (ulonglong)((uint)param_3 & 0x2140);
    local_b8 = 1;
    bVar2 = false;
    bVar23 = false;
    local_c0 = 0;
    local_res18 = uVar21;
    if (local_a8 == 10) {
      pbVar20 = local_res20 + local_80;
      pcVar9 = &DAT_000128dc;
      if (local_80 == 1) {
        iVar5 = 0;
      }
      else {
        iVar5 = (int)(char)pbVar20[1] << 8;
      }
      local_a8 = ((longlong)iVar5 | (ulonglong)*pbVar20) & local_98;
      if (local_a8 != 0xd) {
        pbVar20 = local_res20;
      }
      goto LAB_00009df4;
    }
    if (local_a8 == 0xd) {
      pbVar20 = local_res20 + local_80;
      if (local_80 == 1) {
        iVar5 = 0;
      }
      else {
        iVar5 = (int)(char)pbVar20[1] << 8;
      }
      uVar10 = (longlong)iVar5 | (ulonglong)*pbVar20;
LAB_000098d2:
      local_a8 = uVar10 & local_98;
      if ((uVar10 & local_98) == 10) {
        pcVar9 = &DAT_000128dc;
      }
      else {
        pcVar9 = &DAT_000128e0;
        pbVar20 = local_res20;
      }
      goto LAB_00009df4;
    }
    puVar19 = param_5;
    pbVar20 = local_res20;
    uVar10 = uVar22;
    uVar7 = local_b8;
    if (local_a8 != 0x25) {
LAB_00009646:
      pcVar9 = (char *)&local_a8;
LAB_0000964a:
      uVar21 = uVar21 | 0x400;
      local_res18 = uVar21;
      pbVar20 = local_res20;
      goto LAB_00009df4;
    }
LAB_00009669:
    while( true ) {
      local_b8 = uVar7;
      uVar22 = uVar10;
      local_res20 = pbVar20 + local_80;
      if (local_80 == 1) {
        iVar5 = 0;
      }
      else {
        iVar5 = (int)(char)local_res20[1] << 8;
      }
      local_a8 = ((ulonglong)*local_res20 | (longlong)iVar5) & local_98;
      uVar10 = uVar22;
      uVar7 = local_b8;
      if (local_a8 < 0x2e) break;
      if (local_a8 == 0x2e) {
        uVar21 = uVar21 | 0x800;
        pbVar20 = local_res20;
        local_res18 = uVar21;
      }
      else if (local_a8 == 0x30) {
        if ((uVar21 & 0x800) == 0) {
          uVar21 = uVar21 | 0x20;
          local_res18 = uVar21;
        }
LAB_00009798:
        uVar6 = 0;
        while ((0x2f < local_a8 && (local_a8 < 0x3a))) {
          local_res20 = local_res20 + local_80;
          uVar6 = local_a8 + (uVar6 * 5 + -0x18) * 2;
          if (local_80 == 1) {
            iVar5 = 0;
          }
          else {
            iVar5 = (int)(char)local_res20[1] << 8;
          }
          local_a8 = ((ulonglong)*local_res20 | (longlong)iVar5) & local_98;
        }
        pbVar20 = local_res20 + -local_80;
        uVar10 = uVar6;
        local_c0 = uVar6;
        uVar7 = uVar6;
        if ((uVar21 & 0x800) == 0) {
          uVar21 = uVar21 | 0x200;
          local_a0 = uVar6;
          uVar10 = uVar22;
          local_res18 = uVar21;
          uVar7 = local_b8;
        }
      }
      else {
        if (local_a8 < 0x31) goto LAB_00009823;
        if (local_a8 < 0x3a) goto LAB_00009798;
        if ((local_a8 - 0x4c & 0xffffffffffffffdf) != 0) goto LAB_00009823;
        uVar21 = uVar21 | 0x10;
        pbVar20 = local_res20;
        local_res18 = uVar21;
      }
    }
    if (local_a8 == 0x2d) {
      uVar21 = uVar21 | 1;
      pbVar20 = local_res20;
      local_res18 = uVar21;
      goto LAB_00009669;
    }
    if (local_a8 != 0) {
      if (local_a8 == 0x20) {
        uVar21 = uVar21 | 4;
        pbVar20 = local_res20;
        local_res18 = uVar21;
      }
      else if (local_a8 == 0x2a) {
        if ((uVar21 & 0x800) == 0) {
          uVar21 = uVar21 | 0x200;
          if (puVar17 == (ulonglong *)0x0) {
            local_a0 = *puVar19;
            puVar19 = puVar19 + 1;
            param_5 = puVar19;
          }
          else {
            local_a0 = *puVar17;
            puVar17 = puVar17 + 1;
            local_b0 = puVar17;
          }
          pbVar20 = local_res20;
          local_res18 = uVar21;
        }
        else if (puVar17 == (ulonglong *)0x0) {
          uVar10 = *puVar19;
          puVar19 = puVar19 + 1;
          pbVar20 = local_res20;
          param_5 = puVar19;
          uVar7 = uVar10;
        }
        else {
          uVar10 = *puVar17;
          puVar17 = puVar17 + 1;
          pbVar20 = local_res20;
          uVar7 = uVar10;
          local_b0 = puVar17;
        }
      }
      else if (local_a8 == 0x2b) {
        uVar21 = uVar21 | 2;
        pbVar20 = local_res20;
        local_res18 = uVar21;
      }
      else {
        if (local_a8 != 0x2c) goto LAB_00009823;
        uVar21 = uVar21 | 8;
        pbVar20 = local_res20;
        local_res18 = uVar21;
      }
      goto LAB_00009669;
    }
    uVar22 = 0;
    local_b8 = 0;
    local_res20 = pbVar20;
LAB_00009823:
    pbVar20 = local_res20;
    if (local_a8 < 0x68) {
      if (local_a8 == 0x67) {
        if (puVar17 == (ulonglong *)0x0) {
          uVar22 = *puVar19;
          param_5 = puVar19 + 1;
        }
        else {
          uVar22 = *puVar17;
          local_b0 = puVar17 + 1;
        }
        if (uVar22 == 0) {
          pcVar9 = s_<null_guid>_00012860;
        }
        else {
          FUN_0000a220();
          pcVar9 = (char *)&local_70;
          uVar6 = local_c0;
        }
        bVar2 = false;
        uVar22 = local_b8;
        goto LAB_00009df4;
      }
      if (local_a8 == 10) {
        pbVar20 = local_res20 + local_80;
        pcVar9 = &DAT_000128dc;
        if (local_80 == 1) {
          iVar5 = 0;
        }
        else {
          iVar5 = (int)(char)pbVar20[1] << 8;
        }
        local_a8 = ((longlong)iVar5 | (ulonglong)*pbVar20) & local_98;
        if (local_a8 != 0xd) {
          pbVar20 = local_res20;
        }
        goto LAB_00009df4;
      }
      if (local_a8 == 0xd) {
        pbVar20 = local_res20 + local_80;
        if (local_80 == 1) {
          iVar5 = 0;
        }
        else {
          iVar5 = (int)(char)pbVar20[1] << 8;
        }
        uVar10 = (longlong)iVar5 | (ulonglong)*pbVar20;
        goto LAB_000098d2;
      }
      if (local_a8 == 0x53) goto LAB_00009abb;
      if (local_a8 == 0x58) goto LAB_00009bb0;
      if (local_a8 == 0x61) goto LAB_00009ac4;
      if (local_a8 == 99) {
        if (puVar17 == (ulonglong *)0x0) {
          uVar1 = (ushort)*puVar19;
          param_5 = puVar19 + 1;
        }
        else {
          uVar1 = (ushort)*puVar17;
          local_b0 = puVar17 + 1;
        }
        local_88 = (ulonglong)uVar1;
        pcVar9 = (char *)&local_88;
        goto LAB_0000964a;
      }
      if (local_a8 != 100) goto LAB_00009646;
    }
    else {
      if (local_a8 == 0x70) {
        uVar21 = uVar21 & 0xffffffffffffffd9 | 0x10;
LAB_00009bb0:
        uVar21 = uVar21 | 0x20;
LAB_00009bb4:
        uVar21 = uVar21 | 0x80;
      }
      else {
        if (local_a8 == 0x72) {
          if (puVar17 == (ulonglong *)0x0) {
            uVar10 = *puVar19;
            param_5 = puVar19 + 1;
          }
          else {
            uVar10 = *puVar17;
            local_b0 = puVar17 + 1;
          }
          pcVar9 = (char *)&local_70;
          if ((longlong)uVar10 < 0) {
            if ((uVar10 & 0x7fffffffffffffff) - 1 < 0x21) {
              pcVar15 = (char *)((uVar10 & 0x7fffffffffffffff) * 0x15);
              pcVar9 = s_Warning_Stale_Data_0001296d + 0xe;
LAB_00009b77:
              pcVar9 = pcVar9 + (longlong)pcVar15;
              if (pcVar9 != (char *)&local_70) goto LAB_00009df4;
            }
          }
          else if (uVar10 < 6) {
            pcVar9 = (char *)(uVar10 * 0x19);
            pcVar15 = s_Success_000128f0;
            goto LAB_00009b77;
          }
          FUN_0000a220();
          uVar6 = local_c0;
          goto LAB_00009df4;
        }
        if (local_a8 == 0x73) {
LAB_00009abb:
          uVar21 = uVar21 | 0x400;
          local_res18 = uVar21;
LAB_00009ac4:
          if (puVar17 == (ulonglong *)0x0) {
            pcVar9 = (char *)*puVar19;
            param_5 = puVar19 + 1;
          }
          else {
            pcVar9 = (char *)*puVar17;
            local_b0 = puVar17 + 1;
          }
          if ((ulonglong *)pcVar9 == (ulonglong *)0x0) {
            uVar21 = uVar21 & 0xfffffffffffffbff;
            pcVar9 = s_<null_string>_00012850;
            local_res18 = uVar21;
          }
          uVar22 = uVar22 & -(ulonglong)((uVar21 & 0x800) != 0);
          goto LAB_00009df4;
        }
        if (local_a8 == 0x74) {
          if (puVar17 == (ulonglong *)0x0) {
            uVar10 = *puVar19;
            param_5 = puVar19 + 1;
          }
          else {
            local_b0 = puVar17 + 1;
            uVar10 = *puVar17;
          }
          if (uVar10 == 0) {
            pcVar9 = s_<null_time>_000128a8;
          }
          else {
            FUN_0000a220();
            pcVar9 = (char *)&local_70;
            uVar6 = local_c0;
          }
          goto LAB_00009df4;
        }
        if (local_a8 != 0x75) {
          if (local_a8 != 0x78) goto LAB_00009646;
          goto LAB_00009bb4;
        }
      }
      if (-1 < (char)uVar21) {
        uVar21 = uVar21 & 0xfffffffffffffffd | 0x4000;
      }
    }
    if ((uVar21 & 0x10) == 0) {
      if (puVar17 == (ulonglong *)0x0) {
        uVar6 = (ulonglong)(int)*puVar19;
        param_5 = puVar19 + 1;
      }
      else {
        uVar6 = (ulonglong)(int)*puVar17;
LAB_00009c09:
        local_b0 = puVar17 + 1;
      }
    }
    else {
      if (puVar17 != (ulonglong *)0x0) {
        uVar6 = *puVar17;
        goto LAB_00009c09;
      }
      uVar6 = *puVar19;
      param_5 = puVar19 + 1;
    }
    cVar4 = ((byte)uVar21 & 4) << 3;
    if ((uVar21 & 2) != 0) {
      cVar4 = '+';
    }
    bVar23 = (uVar21 & 8) != 0;
    if ((char)(byte)uVar21 < '\0') {
      uVar16 = 0x10;
      bVar23 = false;
      if (((uVar21 & 0x10) == 0) && (uVar18 = 0x10, (longlong)uVar6 < 0)) {
LAB_00009c91:
        uVar16 = uVar18;
        uVar6 = uVar6 & 0xffffffff;
      }
    }
    else {
      uVar16 = 10;
      if ((uVar21 & 8) != 0) {
        uVar21 = uVar21 & 0xffffffffffffffdf;
        uVar22 = 1;
      }
      if (((longlong)uVar6 < 0) && (uVar21 >> 0xe == 0)) {
        cVar4 = '-';
        uVar6 = -uVar6;
      }
      else {
        uVar18 = 10;
        if (((uint)uVar21 & 0x4010) == 0x4000) goto LAB_00009c91;
      }
    }
    local_70._0_1_ = '\0';
    pcVar9 = (char *)&local_70;
    uVar10 = uVar6;
    do {
      uVar7 = uVar10 / uVar16;
      pcVar9 = pcVar9 + 1;
      *pcVar9 = s_0123456789ABCDEFB_00012c50[uVar10 % (ulonglong)uVar16];
      uVar10 = uVar7;
    } while (uVar7 != 0);
    local_c0 = (longlong)pcVar9 - (longlong)&local_70;
    if (uVar6 == 0) {
      local_c0 = local_c0 & -(ulonglong)(uVar22 != 0);
    }
    pcVar9 = (char *)((longlong)&local_70 + local_c0);
    local_90 = 3 - local_c0 % 3;
    if (local_c0 % 3 == 0) {
      local_90 = 0;
    }
    if ((bVar23) && (local_c0 != 0)) {
      local_c0 = local_c0 + (local_c0 - 1) / 3;
    }
    if (cVar4 != '\0') {
      local_c0 = local_c0 + 1;
      uVar22 = uVar22 + 1;
    }
    uVar21 = uVar21 | 0x1000;
    bVar2 = true;
    uVar6 = local_c0;
    local_res18 = uVar21;
    if (((uint)uVar21 & 0xa21) == 0x220) {
      uVar22 = local_a0;
    }
LAB_00009df4:
    local_res20 = pbVar20;
    uVar16 = (uint)uVar21;
    lVar13 = (ulonglong)((uVar21 & 0x400) != 0) + 1;
    uVar18 = (-(uint)((uVar21 & 0x400) != 0) & 0xff00) + 0xff;
    if ((uVar21 >> 0xc & 1) == 0) {
      uVar6 = 0;
      pcVar15 = (char *)((longlong)pcVar9 + 1);
      while ((((local_c0 = uVar6, pcVar15[-1] != '\0' ||
               (((uVar21 & 0x400) != 0 && (*pcVar15 != '\0')))) &&
              ((uVar6 < uVar22 || ((uVar21 >> 0xb & 1) == 0)))) &&
             ((uVar18 & (int)CONCAT11(*pcVar15,pcVar15[-1])) != 0))) {
        uVar6 = uVar6 + 1;
        pcVar15 = pcVar15 + lVar13;
      }
    }
    else {
      lVar13 = -lVar13;
    }
    if (uVar22 < uVar6) {
      uVar22 = uVar6;
    }
    uVar10 = (ulonglong)(uVar16 & 0x201);
    local_48 = uVar10;
    pcVar15 = local_d8;
    if (uVar10 == 0x200) {
      local_d0 = local_d0 + (local_a0 - uVar22) * uVar14;
      if (((uVar21 >> 0xd & 1) == 0) && (param_1 != (char *)0x0)) {
        param_1 = FUN_00009484(param_1,local_d8,local_a0 - uVar22,0x20,uVar14);
      }
    }
    uVar7 = uVar14;
    if (bVar2) {
      if (((cVar4 != '\0') && (local_d0 = local_d0 + uVar14, (uVar21 >> 0xd & 1) == 0)) &&
         (param_1 != (char *)0x0)) {
        lVar11 = 0;
        do {
          if (local_d8 <= param_1) break;
          *param_1 = cVar4;
          if (uVar14 != 1) {
            param_1[1] = '\0';
          }
          param_1 = param_1 + uVar14;
          lVar11 = lVar11 + 1;
        } while (lVar11 < 1);
      }
      local_d0 = local_d0 + (uVar22 - uVar6) * uVar14;
      if (((uVar21 & 0x2000) == 0) && (param_1 != (char *)0x0)) {
        param_1 = FUN_00009484(param_1,local_d8,uVar22 - uVar6,(ulonglong)((uVar16 & 0x2000) + 0x30)
                               ,uVar14);
      }
    }
    else {
      local_d0 = local_d0 + (uVar22 - uVar6) * uVar14;
      if (((uVar21 & 0x2000) == 0) && (param_1 != (char *)0x0)) {
        param_1 = FUN_00009484(param_1,pcVar15,uVar22 - uVar6,(ulonglong)((uVar16 & 0x2000) + 0x20),
                               uVar14);
      }
      if (((cVar4 != '\0') && (local_d0 = local_d0 + uVar7, (uVar21 & 0x2000) == 0)) &&
         (param_1 != (char *)0x0)) {
        lVar11 = 0;
        do {
          if (local_d8 <= param_1) break;
          *param_1 = cVar4;
          if (uVar7 != 1) {
            param_1[1] = '\0';
          }
          param_1 = param_1 + uVar7;
          lVar11 = lVar11 + 1;
        } while (lVar11 < 1);
      }
    }
    uVar6 = (ulonglong)(cVar4 != '\0');
    param_3 = uVar21;
    lVar11 = local_90;
    do {
      uVar3 = uVar6;
      if ((local_c0 <= uVar3) ||
         ((param_3 = local_res18, uVar10 = local_48, (char)*(ulonglong *)pcVar9 == '\0' &&
          ((lVar13 < 2 || (*(char *)((longlong)pcVar9 + 1) == '\0')))))) goto LAB_0000a137;
      local_d0 = local_d0 + uVar7;
      uVar16 = (ushort)*(ulonglong *)pcVar9 & uVar18;
      if (((uVar21 & 0x2000) == 0) && (param_1 != (char *)0x0)) {
        lVar12 = 0;
        do {
          if (local_d8 <= param_1) break;
          *param_1 = (char)uVar16;
          if (uVar7 != 1) {
            param_1[1] = (char)(uVar16 >> 8);
          }
          param_1 = param_1 + uVar7;
          lVar12 = lVar12 + 1;
        } while (lVar12 < 1);
      }
      pcVar9 = (char *)((longlong)pcVar9 + lVar13);
      uVar6 = uVar3 + 1;
      if ((bVar23) && (lVar11 = lVar11 + 1, lVar11 == 3)) {
        lVar12 = 0;
        uVar6 = uVar3 + 2;
        if (local_c0 <= uVar6) goto LAB_0000a137;
        local_d0 = local_d0 + uVar7;
        lVar11 = lVar12;
        if (((uVar21 & 0x2000) == 0) && (param_1 != (char *)0x0)) {
          lVar8 = 0;
          do {
            lVar11 = lVar12;
            if (local_d8 <= param_1) break;
            *param_1 = ',';
            if (uVar7 != 1) {
              param_1[1] = '\0';
            }
            param_1 = param_1 + uVar7;
            lVar8 = lVar8 + 1;
            lVar11 = 0;
          } while (lVar8 < 1);
        }
      }
    } while( true );
  }
  lVar13 = 0;
  if ((param_3 >> 0xd & 1) != 0) {
    return local_d0 / uVar14;
  }
  pcVar9 = param_1;
  do {
    if (local_d8 + uVar14 <= pcVar9) break;
    *pcVar9 = '\0';
    if (uVar14 != 1) {
      pcVar9[1] = '\0';
    }
    pcVar9 = pcVar9 + uVar14;
    lVar13 = lVar13 + 1;
  } while (lVar13 < 1);
  return ((longlong)param_1 - (longlong)local_78) / (longlong)uVar14;
LAB_0000a137:
  if (uVar10 == 0x201) {
    local_d0 = local_d0 + (local_a0 - uVar22) * uVar7;
    if (((uVar21 & 0x2000) == 0) && (param_1 != (char *)0x0)) {
      param_1 = FUN_00009484(param_1,local_d8,local_a0 - uVar22,0x20,uVar7);
    }
  }
  local_res20 = local_res20 + local_80;
  if (local_80 == 1) {
    iVar5 = 0;
  }
  else {
    iVar5 = (int)(char)local_res20[1] << 8;
  }
  local_a8 = ((longlong)iVar5 | (ulonglong)*local_res20) & local_98;
  puVar17 = local_b0;
  goto LAB_0000a1b8;
}


/* 0xC064 resolves {'status': 'resolved', 'address': '0xc064', 'name': 'FUN_0000c064'} */

/* WARNING: Type propagation algorithm not settling */

longlong FUN_0000c064(ushort *param_1,longlong *param_2,uint param_3,ulonglong param_4,int *param_5)

{
  longlong lVar1;
  ulonglong uVar2;
  wchar_t *pwVar3;
  wchar_t wVar4;
  wchar_t *pwVar5;
  ulonglong *puVar6;
  byte bVar7;
  undefined **ppuVar8;
  undefined4 local_dc8;
  undefined4 local_dc4;
  undefined4 local_dc0;
  undefined4 local_dbc;
  undefined4 local_db8;
  undefined4 local_db4;
  undefined4 local_db0;
  undefined4 local_dac;
  ulonglong local_da8;
  undefined4 local_da0;
  undefined4 local_d9c;
  undefined4 local_d98;
  undefined4 local_d94;
  ulonglong local_d90 [404];
  char local_ee;
  
  local_db4 = 0x47e4fb8e;
  local_db0 = 0xec391abc;
  local_db8 = 0x5855ce1b;
  local_dac = 0xcf960caa;
  local_d90[2] = 8;
  local_da0 = 0x2441822e;
  local_d9c = 0x4d667e0c;
  local_d98 = 0xb2c9328f;
  local_d94 = 0x340ceea;
  if (DAT_00011b91 == -1) {
    FUN_0000ffe0((undefined4 *)(local_d90 + 3),0,0xd46);
    local_da8 = 0xd46;
    lVar1 = FUN_00004cac((ushort *)u_Setup_00012e20,(longlong *)&DAT_00011250,(uint *)0x0,&local_da8
                         ,local_d90 + 3);
    if (-1 < lVar1) {
      DAT_00011b91 = local_ee;
    }
  }
  if (DAT_00011b91 == '\0') {
    uVar2 = FUN_0000c638(param_1,param_2);
    if ((char)uVar2 != '\0') {
      return -0x7fffffffffffffed;
    }
    lVar1 = FUN_0000a918(param_2,(longlong *)&local_db8,0x10);
    if (lVar1 == 0) {
      pwVar5 = u__SETADMINPASSWD_00012e30;
      wVar4 = *param_1;
      pwVar3 = (wchar_t *)param_1;
      while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
        pwVar3 = pwVar3 + 1;
        pwVar5 = pwVar5 + 1;
        wVar4 = *pwVar3;
      }
      if (*pwVar3 == *pwVar5) {
        return -0x7fffffffffffffed;
      }
    }
    if (lVar1 == 0) {
      pwVar3 = u__SETUSERPASSWD_00012e50;
      for (; (*param_1 != L'\0' && (*param_1 == *pwVar3)); param_1 = param_1 + 1) {
        pwVar3 = pwVar3 + 1;
      }
      if (*param_1 == *pwVar3) {
        return -0x7fffffffffffffed;
      }
    }
    return -0x7ffffffffffffffd;
  }
  pwVar5 = u_NvLockMailbox_00012e00;
  wVar4 = *param_1;
  pwVar3 = (wchar_t *)param_1;
  while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
    pwVar3 = pwVar3 + 1;
    pwVar5 = pwVar5 + 1;
    wVar4 = *pwVar3;
  }
  if ((*pwVar3 == *pwVar5) &&
     (lVar1 = FUN_0000a918(param_2,(longlong *)&DAT_00011b98,0x10), lVar1 == 0)) {
    return (ulonglong)(-(uint)((param_3 & 4) != 0) & 0xc) + 0x8000000000000003;
  }
  if (DAT_000132e0 == 0) {
    if (DAT_0001342a == '\0') {
      local_da8 = local_da8 & 0xffffffff00000000;
      puVar6 = &local_da8;
      local_d90[0] = 0;
      local_dc8 = 0x5855ce1b;
      local_dc4 = 0x47e4fb8e;
      local_dc0 = 0xec391abc;
      local_dbc = 0xcf960caa;
      lVar1 = FUN_00004cac((ushort *)u__SETUPPASSWD_00012ea0,(longlong *)&local_dc8,(uint *)puVar6,
                           local_d90,(undefined8 *)0x0);
      if (lVar1 != -0x7ffffffffffffff2) {
        puVar6 = (ulonglong *)0x0;
        FUN_000052d4((ushort *)u__SETUPPASSWD_00012ea0,(longlong *)&local_dc8,0,(undefined *)0x0,
                     (longlong *)0x0);
      }
      local_da8 = 0;
      local_d90[1] = 0;
      local_d90[0] = 0;
      FUN_0000bd28(&DAT_00011050,&LAB_0000bd80,puVar6,(undefined8 *)&local_dc8,local_d90);
      FUN_0000bd28(&DAT_00011070,&LAB_0000be20,puVar6,(undefined8 *)&DAT_00013430,&local_da8);
      FUN_0000a858();
      DAT_0001342a = '\x01';
      if (DAT_000132e0 != 0) goto LAB_0000c378;
    }
  }
  else {
LAB_0000c378:
    if ((DAT_0001343b == '\0') && (DAT_00013249 == '\x01')) {
      FUN_0000bed8();
      DAT_0001343b = '\x01';
    }
    if (((DAT_000133fa == '\0') && (DAT_000132e0 != 0)) &&
       (lVar1 = (**(code **)(DAT_000132e0 + 0x28))(DAT_000132e0,&DAT_00011bb0,&PTR_LAB_00011ba8,8),
       lVar1 == 0)) {
      DAT_000133fa = '\x01';
    }
    if ((DAT_0001343c == '\0') &&
       (lVar1 = (**(code **)(DAT_000132e0 + 0x28))(DAT_000132e0,&local_da0,&DAT_00011b90,1),
       lVar1 == 0)) {
      DAT_0001343c = '\x01';
    }
  }
  if (((DAT_000133f9 == '\0') && (DAT_0001343b == '\0')) &&
     (lVar1 = FUN_00004cac((ushort *)u_NvLockMailbox_00012e00,(longlong *)&DAT_00011b98,(uint *)0x0,
                           local_d90 + 2,&DAT_000135c0), lVar1 == 0)) {
    DAT_0001343d = DAT_000135c0 == 1;
  }
  lVar1 = -0x7ffffffffffffffd;
  ppuVar8 = &PTR_FUN_00012e90;
  do {
    if (lVar1 != -0x7ffffffffffffffd) {
      return lVar1;
    }
    lVar1 = (*(code *)*ppuVar8)(param_1,param_2,param_3,param_4,param_5);
    ppuVar8 = ppuVar8 + 1;
  } while (*ppuVar8 != (undefined *)0x0);
  if (lVar1 != -0x7ffffffffffffffd) {
    return lVar1;
  }
  bVar7 = -(DAT_00011b90 != '\0') & DAT_0001343d;
  lVar1 = FUN_0000a918(param_2,(longlong *)&local_db8,0x10);
  if (lVar1 == 0) {
    pwVar5 = u__SETADMINPASSWD_00012e30;
    wVar4 = *param_1;
    pwVar3 = (wchar_t *)param_1;
    while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
      pwVar3 = pwVar3 + 1;
      pwVar5 = pwVar5 + 1;
      wVar4 = *pwVar3;
    }
    if (*pwVar3 != *pwVar5) goto LAB_0000c522;
LAB_0000c559:
    if (DAT_0001343d == 0) {
      if ((1 < param_4) &&
         (*(short *)((longlong)param_5 + ((param_4 & 0xfffffffffffffffe) - 2)) == 0)) {
        param_4 = param_4 - 2;
      }
      if (param_4 - 6 < 0x23) {
        lVar1 = FUN_0000c8ac((short *)param_1,(undefined8 *)param_5,param_4);
        if (lVar1 == 0) {
          lVar1 = -0x7fffffffffffffa1;
        }
      }
      else {
        lVar1 = -0x7ffffffffffffffe;
      }
    }
    else {
      lVar1 = -0x7fffffffffffffe6;
    }
  }
  else {
LAB_0000c522:
    if (lVar1 == 0) {
      pwVar5 = u__SETUSERPASSWD_00012e50;
      wVar4 = *param_1;
      pwVar3 = (wchar_t *)param_1;
      while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
        pwVar3 = pwVar3 + 1;
        pwVar5 = pwVar5 + 1;
        wVar4 = *pwVar3;
      }
      if (*pwVar3 == *pwVar5) goto LAB_0000c559;
    }
    lVar1 = -0x7ffffffffffffffd;
    if (((DAT_00013290 != '\0') && (bVar7 != 0)) && (DAT_000133f9 == '\0')) {
      uVar2 = FUN_00008bc0((short *)param_1,param_2,(ulonglong)param_3,param_4,param_5);
      lVar1 = -0x7ffffffffffffffd;
      if ((longlong)uVar2 < 0) {
        lVar1 = -0x7fffffffffffffe6;
      }
    }
  }
  return lVar1;
}

