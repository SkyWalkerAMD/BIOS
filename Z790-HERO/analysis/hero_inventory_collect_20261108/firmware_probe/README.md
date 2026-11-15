# 只读固件身份探针 I1

供 SMBIOS 采集器整合的独立模块，未连接设备、未修改现有 BIOS、未生成或刷写 CAP。用途是核对固件公开的 R2/P5/P6 文件是否存在，以及对应映像是否当前加载；不调用模块入口、初始化、协议安装、变量写入、BMC 或 PCI 接口。

## 接入

编译 `firmware_probe.c`，包含目录设为采集器的 `source` 和本目录；链接现有 `common.c` 与 `kvm.c`，使用其中的内存函数和 `probe_crc32`。

```c
#include "firmware_probe.h"
static void inventory_append(void *context,const char *bytes,size_t length) {
    (void)context;
    add_n(bytes,(UN)length); /* 采集器原有有界 RAM 日志追加函数 */
}
/* 建议单独的只读 F 操作；按键处理仍由采集器负责。 */
ES status=firmware_probe(gST,inventory_append,0);
```

模块不会清空上层日志。回调同步复制传入字节，不保留局部字符串指针。完整输出不超过 128 KiB；调用方应预留该空间。返回 `EFI_COMPROMISED_DATA` (`0x8000000000000021`) 表示枚举或读取不完整，应保留日志中的具体状态，不解释成“模块损坏”。

## 证据与判断边界

1. 使用 LoadedImage 协议枚举和完整 DevicePath 中的 `MEDIA_PIWG_FW_FILE_DP` GUID，定位 R2 与共享 P5/P6 FFS GUID。记录匹配句柄、设备句柄、映像地址、大小及有界运行内存 CRC。
2. 使用 FV2 `ReadFile(Buffer=NULL)` 仅查询文件存在性、大小和类型；这是规范定义的无文件输出分配方式。
3. 对已找到且大小合规的文件，使用预先提供的 1 MiB 缓冲区调用 `ReadSection(PE32, instance=0)`，记录完整 PE 的大小、CRC32、认证状态和基本 PE 签名／Machine。仅精确成功且缓冲区契约有效时计算 CRC；警告返回不算完整文件。
4. `FV_FILES>0` 是该 GUID 文件在本次公开固件卷中存在的正面证据。`LOADED_MATCHES>0` 只说明映像当前加载，不保证入口成功、API 发布或初始化成功。
5. 文件存在但没有加载匹配，只能表述为“当前未找到加载匹配”，不能区分从未调度、入口失败卸载、其他路径加载等原因。
6. 两者都是零仍不能单独判断 RC2、RC3 或闪存完整内容。固件卷可能未公开或不允许读取，DevicePath 可能不匹配，枚举也可能受边界限制。

`FP_LOADED_MEMORY_CRC32` 含重定位和可变全局数据，不应拿它与原始 EFI 文件的 CRC 比较。应对比 `FP_FV_PE_BYTES` 和 `FP_FV_PE_CRC32`；CRC32+大小是诊断指纹，不是密码学证明。

本地归档文件对照（`known-pe-images.json` 包含 SHA256 和来源校验）：

| 归档模块 | PE 大小 | CRC32 |
| --- | ---: | --- |
| RC3 提取 R2 | 22,016 | `1D66102E` |
| RC3 提取 P5，RC2/RC3 共用 | 348,160 | `88B7A375` |
| RC4 候选 P6 | 373,248 | `EE63A8A8` |

以上不是当前机器的读取结果。

## 边界与 ABI

- LoadedImage 句柄最多 1,024 个，FV2 句柄最多 64 个；超限则不遍历该列表，并标记不完整。
- DevicePath 最多 4,096 字节、128 个节点，节点长度和终止节点均检查。仅匹配完整有效路径。
- 最多 16 个匹配映像，单个已加载映像 CRC 最大 2 MiB，单个 FV PE 最大 1 MiB，全部 CRC 数据预算 8 MiB。
- 内存映射最大 128 KiB、2,048 条描述符；解引用协议、路径及映像前检查其处于可读的已分配 RAM／ACPI 区域，拒绝 MMIO、保留、空闲、读保护及越界范围。一次固件内存映射是检查依据，不保证有缺陷的固件服务本身不会出错。
- 采用标准 x64 UEFI ABI，静态断言检查 LoadedImage、Boot Services 和 FV2 的相关偏移。官方 `edk2-stable202502` 头文件和 SHA256 见 `provenance.json`；`EFI_FV_FILETYPE=UINT8`、`EFI_FV_FILE_ATTRIBUTES=UINT32` 已核对。
- 模块只调用 `GetMemoryMap`、`LocateHandleBuffer`、`HandleProtocol`、`FreePool` 及 FV2 的两个读取函数。没有刷写、变量写入、驱动加载／启动、BMC、PCI 或重启动作。

## 离线验证

`tests.json` 记录 14 项 host 测试通过，执行真实编译 C 代码并模拟 UEFI 服务：同时找到文件和映像、只有 FV 文件、未找到 R2、读取警告／数据超限、异常返回指针、缓冲区哨兵损坏、坏路径、MMIO 路径、过量句柄、内存映射失败、读取拒绝和重入拒绝，以及 10,000 条随机 DevicePath。

模拟正常输出见 `mock-normal-transcript.txt`。所有输入和服务均在本地进程中模拟，不能列为真实 `.71` 读回验证。采集器主代理负责后续 ISO 整合和实机采集。
