# HERO IPMI 免刷诊断 A1

这是在目标 HERO 上从 U 盘启动的 UEFI 诊断程序。主板可以继续使用原来的 BIOS 3001；诊断不需要刷入实验 CAP，也不需要另装 UEFI Shell。

**A1 做的是第一阶段的真实硬件取证。它还不是三个移植驱动的内存加载器，不会初始化或启用缺失的主板传感器。**

## 现在怎么运行

1. 准备一个已有 FAT32 分区的备用 U 盘。若需格式化，先处理盘上已有文件；本包没有格式化或刷写工具。
2. 将包内 `USB` 文件夹的**内容**复制到 U 盘根目录。结果应是：

   ```text
   U盘根目录
   ├── EFI
   │   └── BOOT
   │       └── BOOTX64.EFI
   └── HERO-PROBE-USB.TAG
   ```

   不要将整个 `USB` 文件夹再套在 U 盘根目录下。标记文件用于限定日志的写入位置。
3. 在目标 ROG MAXIMUS Z790 HERO 上保持现有 BIOS 3001、扩展卡及 BMC_HEADER 接线。从主板的一次性启动菜单选择 **UEFI 模式的该 U 盘**。这是正常启动程序，不是 EZ Flash 或 FlashBack 更新。
4. 程序先显示主板、BIOS、扩展卡和日志文件名。看到 `P = query BMC...` 后按 **P**，读取 BMC 身份、SDR 目录和可读取的传感器。无需输入 BMC IP、用户名或密码。
5. 如果出现 `R = sample...`，可间隔约 10 秒按 **R** 再采样一两次。没有变化不代表读数一定是快照，数值变化也还不等于通道与单位正确。
6. 按 **Q** 结束查询；看到 `Log closed` 后，再按 **Q** 返回启动菜单。若没有进入查询阶段，只会出现最后一次退出提示。
7. 取回 U 盘根目录的 `HEROIPMI-000.TXT`。重复运行会新建 `001`、`002` 等文件，不覆盖旧日志。把实际日志发回本任务，才有目标实机的证据可供继续适配。

如果界面提示 `LOG UNAVAILABLE`，检查标记文件及文件位置；如果提示日志写入/刷新失败，记录屏幕内容。`example-MOCK-log.txt` 是测试桩的示例，不是用户实机结果。

## 如果 Secure Boot 拒绝启动

`BOOTX64.EFI` 是本地生成的未签名诊断程序。如果启动时报 `Security Violation`，这表示固件拒绝加载它，尚未执行任何 BMC 检查。

ASUS 以 Z790 HERO 为例说明，可在 **Advanced Mode → Boot → Secure Boot → OS Type** 中用 `Other OS` 暂时关闭 Secure Boot；测试后恢复原设置。**不需要清除 Secure Boot 密钥。** 这是一项启动设置调整，与刷写 BIOS 镜像是两回事。参见 [ASUS 主板 Secure Boot 说明](https://www.asus.com/us/support/faq/1049829/)。

若目标 Windows 启用了 BitLocker/设备加密，修改此设置前先确认恢复密钥可用；这类调整可能触发恢复验证。参见 [ASUS Secure Boot 与加密说明](https://www.asus.com/au/support/faq/1050047/)。

## 各结果能证明什么

| 日志/现象 | 可以得出的结论 | 不能直接得出的结论 |
|---|---|---|
| 识别到 `1A03:2402` | 当前启动中的 PCI 枚举看到了与供体驱动匹配的扩展卡功能 | BMC_HEADER 的传感器总线已工作 |
| `KCS gate CLOSED` | 板型、版本、就绪标志、内存使能或 BAR 范围未满足 A1 的检查条件 | 硬件不兼容或移植必定失败 |
| `GET_DEVICE_ID_OK` | 独立诊断程序通过供体使用的主机 KCS 地址成功和 BMC 通信 | R1 的原始 transport 驱动已加载、传感器初始化已成功 |
| `EMPTY_REPOSITORY` | 此次标准 Get SDR Repository Info 返回零条记录 | BMC 没有任何其他 OEM/设备传感器存储 |
| 有完整 SDR，读数为 `READING_UNAVAILABLE` | 此次查询有对应目录，但 BMC 标记该读数不可用 | 原因一定是接线或一定是 BIOS |
| `SCANNING_DISABLED` | BMC 在该传感器响应中报告扫描未启用 | 已经确定应当启用哪组 OEM 参数 |
| `READING_REPORTED` | BMC 返回数据并报告扫描启用、读数可用 | 值必然来自 HERO 主板、单位正确、通道正确或持续实时更新 |
| `TIMEOUT` / `INTERFACE_BUSY` / `PCI_IO_ERROR` | 该次通信没有完成，A1 已停止后续查询 | 卡不支持；接口策略、就绪状态等还需分析 |
| `SDR scan incomplete` | BMC 拒绝整条 SDR 读取，或通信不完整 | 没有传感器。A1 没有为此预留/改写 SDR 仓库 |

日志保留完整请求/响应和原始 SDR，供后续核对传感器名称、编号、类型、换算参数及 BMC 错误码。屏幕上的 `raw=0x..` 不是摄氏度、电压或 RPM。

若整条 SDR 读取不被接受，可以用现有 `ipmitool` 通过 BMC 网络接口补充目录。`-a` 会交互询问密码，不要把密码写入命令或发到对话中：

```text
ipmitool -I lanplus -H <BMC_IP> -U <用户名> -a mc info
ipmitool -I lanplus -H <BMC_IP> -U <用户名> -a sdr elist all
ipmitool -I lanplus -H <BMC_IP> -U <用户名> -a sensor list
```

## 真正验证移植的后续步骤

1. **本包 A1：硬件基线。** 从实际 HERO 取得上述日志，确定主机通信是否成立、有哪些协议及 SDR。
2. **随后制作专门的内存试运行版本。** 根据 A1 结果安排移植组件的初始化顺序，显式触发传感器发布，记录每条 BMC OEM 命令的完成码。这一步才开始测试移植初始化本身。它仍可不刷主板 BIOS，但 OEM 初始化会改变 BMC 配置；不能保证主机重启就撤销这些改变。
3. **检查实际读数。** 核对名称、通道、单位及多次变化，和本机监控的相同传感器比较，区分卡自身传感器、开机快照和主板实时遥测。不能只以 Web 界面出现一行记录作为成功标准。
4. **最后才验证固件内启动。** 即使内存试运行成功，仍不能证明修改后的 CAP 被更新工具接受、被固件认证接受、在冷启动中被发现和正确调度。这部分只能留给有明确恢复条件的后续刷写/启动验证。

现有 `hero_sensor_r1/modules/.../patched.efi` 依赖协议通知和启动事件，不能简单按文件顺序 `load` 后就宣称完成验证。Shell/USB 应用运行时相关事件可能已发生。UEFI 允许内存加载镜像，但调用入口不自动补齐供体假设。参见 [TianoCore 加载 UEFI 驱动说明](https://tianocore-docs.github.io/edk2-UefiDriverWritersGuide/draft/31_testing_and_debugging_uefi_drivers/313_uefi_shell_debugging/3133_loading_uefi_drivers.html)。

## 程序实际做的操作

- 读取 SMBIOS 中的主板型号和 BIOS 版本；不采集序列号、UUID 或网络账号。
- 查询 UEFI 协议是否存在、读取 SecureBoot 状态和扩展卡 PCI 配置。
- 只在型号/版本精确匹配、单张卡、revision 为 `01`、PCI 内存解码已启用、32 位 BAR1 有效且范围足够时开放通信。不主动设置 PCI Command 或总线主控位。
- 按 P 后通过 PCI I/O Protocol 访问 BAR1 偏移 `0xE88`（KCS data）及 `0xE8C`（KCS status/command）。地址来自给定 ProArt transport 固件的静态分析，不是通用 IPMI 卡地址。
- IPMI 白名单仅包含 Get Device ID `06/01`、Get SDR Repository Info `0A/20`、Get SDR `0A/23`、Get Sensor Reading `04/2D`。其中 Get SDR 限定 reservation=0、offset=0、读取整条。上限 128 条记录；不桥接其他传感器所有者。
- 每条 KCS 消息最多 10 秒主动轮询等待；遇到异常停止，不强制抢占忙接口、不发送 abort/reset。这里的“读取”指 IPMI 命令语义，传输本身仍会写 KCS 消息寄存器。
- 新建日志文件并刷新；停止 UEFI 应用的标准启动 watchdog，以便等待按键。没有调用 BMC watchdog 命令。
- 不调用 SetVariable、LoadImage、StartImage、UpdateCapsule、固件更新协议、SPI 编程、PCI 配置写入、OEM 初始化或风扇控制。

自制 UEFI 程序仍可能遇到固件差异或挂起；A1 不包含刷写动作，但不承诺“零风险”。当前没有在目标 HERO 上执行过此文件。

## 构建与检查

源码位于 `source/`。工作区脚本 `analysis/build_hero_ipmi_probe.py` 使用校验过的便携 Zig 0.14.1 中的 Clang/LLD 生成 x64 UEFI application，无系统动态库导入，有重定位、PE 校验和，未签名。包内 `build.json` 记录 SHA-256 和编译命令。

包内 `workspace_scripts/` 是复核脚本副本，按原工作区布局使用：脚本放在 `analysis/`，本目录放在 `analysis/hero_ipmi_probe/`，编译器/Python 依赖在工作区 `tools/`。运行诊断本身只需 `USB/` 中的两个文件，不需要 Python、编译器或这些脚本。

`analysis/verify_hero_ipmi_probe.py` 在 Unicorn 中执行**最终 EFI 文件**，以模拟 EFI/PCI/KCS 测试：正常通信、大小写按键、已有日志、缺少标记、日志失败、无卡、板型不符、内存未启用、未就绪、BAR 类型/范围不符、接口忙、状态全 FF、I/O 失败、超时、响应不匹配、完成码失败、响应过长、空 SDR、损坏 SDR、读数不可用、末尾无 dummy byte 等 22 个场景。检查了栈和整数寄存器约定、分配边界，以及未调用禁止的写入/加载服务。结果在 `verification.json`。

**模拟 BMC 响应不是实机证据。以上检查也不验证 R1 CAP。**

UEFI 可移动介质启动路径与 FAT 文件系统依据：[UEFI Boot Manager](https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html)、[UEFI Media Access](https://uefi.org/specs/UEFI/2.11/13_Protocols_Media_Access.html)。KCS 协议依据 [Intel IPMI 2.0 规范](https://www.intel.com/content/dam/www/public/us/en/documents/specification-updates/ipmi-intelligent-platform-mgt-interface-spec-2nd-gen-v2-0-spec-update.pdf)。所查阅的 EDK II、Linux 和 ipmitool 源码版本/散列列在 `source/reference/sources.json`；参考文件仅用于核对，未链接进程序。
