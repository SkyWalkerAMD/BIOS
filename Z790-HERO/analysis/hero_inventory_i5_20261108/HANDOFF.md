# I5-A 自动 RAM 网络验证包

这是独立只读测试 ISO，尚不是自动库存 BIOS。启动器通过标准 LoadImage/StartImage 加载驻留驱动；驱动在 TPL_APPLICATION 自动尝试一次，以本机 SMBIOS 身份和 .71 固定公开证书绑定，只读取内部 Redfish root 与 System 两个资源。

文件：`HERO-INVENTORY-I5A-READONLY.iso`。SHA-256：`e2d55ac84a374cd3fb5f4725b7d0483af89fb06aec97ce4a0900471ffb6f4f1c`。

## 现场步骤

1. 由主代理在 BIOS 界面确认 NetworkStack 为 Disabled；此程序不会修改该设置。
2. 挂载 ISO，从 UEFI 光驱启动。程序自动进行本次唯一尝试，无需按 D/U/N/P。
3. 出现 `I5_RESIDENT_STATE`、`I5_RESIDENT_RESULT` 后，按 C 截取所有 QR 页，或 V 查看文字。若使用可写同包 U 盘，L 可保存新的 `I5Axxx.TXT`。
4. Q、Q 返回固件。日志驻留在 RAM，重启前完成导出。驱动及其私有网络模块保留到本次主机重置，以免异常清理后仍有回调指向已释放代码。

正确目标会先生成本机 System/CPU/Memory catalogue，但本包不发送该 catalogue。不嵌入用户名密码，不发布库存，不修改 IPMI、看门狗或 BIOS 设置。

## 网络范围与改动

仅接受唯一 ASUS BMC USB 控制/数据接口以及同一物理路径上的 NII/SNP。所有新增 DriverBinding.Supported/Start 都限定在这些句柄及固定哈希的私有 RAM 映像。没有递归 ConnectController，也不载入 PXE、DHCP、HTTP、IPv6 驱动。已存在的目标服务优先复用；原生 TLS 服务缺失则退出。

内嵌 DPC、SNP、MNP、ARP、IPv4、TCP、RNDIS、USB LAN 共 193,216 字节。5 个原生网络模块仅在私有副本中跳过成功读取 NetworkStackVar 后的 enabled 检查；GetVariable 失败仍拒绝。所有补丁前置检查原始 SHA-256 和精确机器码，manifest 保存每处变化。

REA 进一步确认原生 Ip4Config2 初始化会读写 MAC 命名的持久配置。私有 Ip4Dxe 的配置读取助手固定返回 NOT_FOUND、保存助手固定返回成功，不访问持久配置；默认状态仍构建在本次私有实例内存中。原始固件 FFS、系统 RuntimeServices 表均未改动。此新增隔离属于运行行为变化，仍需实机 IPv4/TCP 验证。

## 失败处理及证据范围

- 安装报告协议后，每次启动最多一次尝试；再次启动工具只读取现有结果。
- 非目标主板/BIOS/UUID、异常 SMBIOS、无 BMC USB、缺 TLS、NetworkStackVar 错误或大小不符，均在对应阶段返回；不调用库存写入。
- 传输沿用实测 I3d 的 TLS1.2、精确 leaf pin、严格 HTTP framing 和取消/清理逻辑；证书不匹配时不发送 HTTP。每次交换的自身轮询总预算约 30 秒，超时取消另最多约 1 秒；最多 root/System 两次交换，不自动重试。
- 所有失败都保留状态并返回启动器；没有失败时 ResetSystem、强制重启或变量修复。
- UEFI 的 LoadImage/StartImage、原厂 DriverBinding 和协议方法属于同步固件调用，调用者不能安全抢占挂死的固件实现。因此不能把本程序的轮询预算宣称为任意底层故障下的硬总时限。首次默认 Disabled 实机测试仍是交付门槛。

本地验证：160 个原始/修改后门控机器码情形，6 个 Ip4Config2 无持久访问情形，1,886 个 loader 断言，21 个实际驻留 PE 入口/SMBIOS/失败策略情形。OVMF 完整加载驻留驱动、记录 TPL4、拒绝错误机器、2 页 QR 完整校验并返回固件。网络/TLS 成功和失败响应在 PE 测试中为替身；这些测试不声称实际 .71 USB 链路通过。

## 后续固件集成缺口

`I5AUTONET.EFI` 是 EFI_BOOT_SERVICE_DRIVER，244,224 字节；SizeOfImage 2,961,408 字节，主要含有界日志与 SMBIOS 缓冲。最低 PE32 section 加 4 字节头为 244,228 字节，实际 FFS 还需 UI/DEPEX/FFS 头；外层 LZMA 由父构建器处理。不要把该文件直接作为最终自动库存 FFS 发布。

当前 DriverEntry 可在 TPL_APPLICATION 同步执行，但 ISO 的手工 LoadImage/StartImage 不能证明主板 DXE 原生调度时机。若原生 DXE 入口早于 BMC USB 连接，当前一次性入口会正确失败退出，随后不会自行重试。简单增加 USB_IO DEPEX 也不能证明选定 BMC 设备已出现、SMBIOS 已完整或 BDS 会再次调度。

禁止在 ReadyToBoot 的 TPL_CALLBACK 回调中同步调用当前传输：TCP 完成事件也使用 TPL_CALLBACK，阻塞会阻止完成事件运行。后续应单独验证低 TPL 原生调度入口，或实现真正分步异步状态机，并在 RAM 调度 harness 中重现事件时机。届时再次验证无卡、变量读取失败、pin 变化、传输超时均放行 OS；本包没有冒充完成这一验证。

动态 SMBIOS catalogue 为通用当前机器构造器，单独 .71 身份/证书测试策略隔离于 catalogue。下一阶段接入已冻结 typed PCI/Block/DiskInfo collector 与 PCIe/Storage catalogue，再进行 fresh ETag、对象读回和精确缓存管理；本包无这些写入口。
