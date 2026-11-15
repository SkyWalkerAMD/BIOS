# HERO IPMI 免刷诊断 A2

A2 根据 2026-09-28 的真实 A1 日志修订，支持 **ROG MAXIMUS Z790 HERO，BIOS 3001 / 3107**。本轮可继续使用实机上的 3107。A2 是 UEFI 诊断应用，不是修改后的 BIOS，也不是移植驱动加载器。

## 这次为什么需要 A2

实机已识别出 `1A03:2402` 扩展卡，BAR1 为 `0x74100000`，但 PCI Command 为 `0x0000`，内存解码没有打开。另外，A1 只允许 BIOS 3001，实机实际为 3107。A1 因这两个条件退出，没有发送任何 BMC 命令。

A2 在读取检查通过后提供 **E**：暂时开启该卡的 PCI 内存解码，执行标准 BMC 查询，结束时尝试恢复原内存解码位并读回核实。它只在 PCI Command（偏移 4）进行 **16 位**读改写，改变 Memory Space 位 `0x0002`；不会写邻接的 PCI Status，也不会主动开启 Bus Master 位 `0x0004`。

这是实际硬件寄存器操作，不能将 A2 的 E 模式称为“完全只读”。它不刷 BIOS、不发送 BMC OEM 初始化、不改风扇配置。正常退出和程序可处理的错误路径都会执行恢复检查；程序卡死或断电时，无法保证清理代码执行。

## 使用步骤

1. 将 `USB/` 内的 **EFI 文件夹和 HERO-PROBE-USB.TAG** 复制到原 FAT32 U 盘根目录，替换原诊断程序。保留已有 `HEROIPMI-*.TXT` 日志。
2. 在目标 HERO 上从 U 盘的 UEFI 启动项运行，确认标题为 **HERO IPMI PROBE A2**。
3. 对于本次 `Command=0000` 的情况，看到提示后按 **E**，启动临时启用和查询流程。如果内存解码已经启用，程序显示 **P**，按 P 直接查询。
4. 若有传感器，按 **R** 可再次采样；按 **Q** 结束查询。等程序报告恢复状态及 `Log closed`，再按 **Q** 退出。
5. 将新生成的 `HEROIPMI-xxx.TXT` 发回。原 000 日志若仍在 U 盘，新的通常是 **001**，程序不会覆盖已有文件。

正确文件布局：

```text
U盘根目录/EFI/BOOT/BOOTX64.EFI
U盘根目录/HERO-PROBE-USB.TAG
```

若按 E 前没有可写日志，A2 会停止，避免失去临时寄存器操作的记录。A2 同时接受 A1/A2 的标记文件，但建议复制本包的两个文件。未识别到支持的板型、版本、唯一扩展卡、有效 BAR 类型/范围，或就绪标志未满足时，都不会开启内存解码。

若出现 `PCI_MEMORY_RESTORE_UNCONFIRMED`，记录屏幕与日志，关机重启后再作下一次测试。不能把这种结果当作已恢复。遇到挂起也不能假定清理已经完成。

## 看哪些结果

| 标记 | 含义 |
|---|---|
| `PCI_MEMORY_ENABLED_VERIFIED` | 临时设置后，PCI Command 读回符合预期；通常是 `0000 → 0002` |
| `GET_DEVICE_ID_OK` | 独立诊断程序已通过主机 KCS 接口收到有效的 BMC 身份响应 |
| `SDR_SCAN_COMPLETE` | 完成此次标准 SDR 仓库遍历；不代表全部主板传感器存在或正常 |
| `EMPTY_REPOSITORY` | 此次标准 SDR 仓库返回零记录；不能扩大为 BMC 完全没有传感器 |
| `READING_UNAVAILABLE` / `SCANNING_DISABLED` | BMC 在相应传感器响应中报告读数不可用或扫描未启用 |
| `READING_REPORTED` | BMC 返回可用读数；仍须核对来自哪个传感器、换算单位及实时性 |
| `PCI_MEMORY_RESTORED_VERIFIED` | 清理阶段读回确认内存解码位恢复；本次原值为 0 时通常为 `0002 → 0000` |
| `PCI_OTHER_COMMAND_BITS_CHANGED` | 其他 Command 位出现变化；A2 保留它们，不能宣称整个寄存器与开始时完全相同 |
| `PCI_MEMORY_RESTORE_UNCONFIRMED` | 清理未能确认恢复，需要保留记录并关机重启 |

如果 Get SDR 被拒绝，A2 会保留完成码并停止该次遍历；它没有添加 SDR 预留或分块读取操作。如果 KCS 忙、超时或 I/O 失败，会停止后续查询并进入恢复流程，不强制重置 BMC。

## 协议名称更正

A1 把 `72338391-FB43-44A1-A9A2-64FEE1FC5E41` 错标为 `PCI enumeration complete`。它是在供体初始化驱动中观察到的通知 GUID，具体身份尚未确认。

标准 PI PCI Enumeration Complete 协议是 **`30CFE3E7-3DE1-4586-BE20-DEABA1B3B793`**。A2 分开查询这两个 GUID；A1 日志中的 ABSENT 只适用于 72338391，不能推导标准协议不存在或 PCI 枚举失败。已有 PCI I/O 句柄及设备配置正是可用的枚举结果。参见 [EDK II 定义](https://github.com/tianocore/edk2/blob/edk2-stable202502/MdePkg/Include/Protocol/PciEnumerationComplete.h)。

R1 实验 BIOS 把供体通知 GUID 写进了硬性启动依赖，这部分需要重做并验证。R1 仍是基于 **3001** 的历史实验文件，不因 A2 支持 3107 就成为 3107 的适配镜像。详细结论见 `A1日志分析.md`。

## 操作范围与验证

- 查询 SMBIOS、SecureBoot、指定 UEFI 协议、扩展卡 PCI 配置及 BAR 资源。
- 按 E 后才允许临时改动目标 PCI Command 的内存解码位，按 Q 不触发该操作；已有内存解码时，P 路径不写 PCI 配置。
- 只向 BAR1 `+0xE88/+0xE8C` 的 KCS 消息寄存器发送标准读取命令：`06/01`、`0A/20`、`0A/23`、`04/2D`。总线传输本身需要写消息寄存器。
- 不访问 BIOS 3001 专属的 Setup/HWM 字段；3107 的板级传感器表仍须另行核对。
- 不发送 OEM 命令、不调用 SetVariable/LoadImage/StartImage/UpdateCapsule，不进行 SPI 编程。
- 日志只写入有标记文件的启动卷，按序新建；程序停用标准 UEFI 应用 watchdog 以允许等待按键。

编译产物为未签名 x64 UEFI application。PE 结构、重定位、校验和及无动态库导入检查通过。最终 EFI 在 Unicorn 的 **48 个模拟场景**中执行通过，覆盖实际日志里的 PCI 配置/3107、E/Q 路径、启用失败、部分写入后报错、通信超时、恢复失败、恢复读回失败及旧日志保护。模拟的 BMC 响应仍然是测试数据，**A2 尚未在目标实机运行，也未验证 R1**。

`example-MOCK-log.txt` 只供辨认输出格式；真实原始日志在 `evidence/`。`build.json`、`verification.json` 与 `SHA256SUMS.txt` 记录构建和验证结果。源码在 `source/`。复核脚本在 `workspace_scripts/`，按原工作区结构放回 `analysis/` 使用；运行诊断只需 `USB/` 的两个文件。

PCI 配置访问依据：[UEFI PCI I/O Protocol](https://uefi.org/specs/UEFI/2.10/14_Protocols_PCI_Bus_Support.html#efi-pci-io-protocol-pci-write)。Command 位定义见包内查阅的 `source/reference/Pci22.h`，来源及散列记录在 `sources.json`。
