# I5-B：标准驱动绑定入口与默认禁用网络栈验证

本包替代 I5-A 的实机测试资格。I5-A 保持原样，但进一步审计发现其私有 DriverBinding 仍可被随后 BDS 用于其他 NIC，所以不再执行旧包。

ISO：`HERO-INVENTORY-I5B-READONLY.iso`

SHA-256：`d5c063e447b9f36fd1a38a39ef5dc300d85c816683626f7c02bb3742087a632b`

本包只 GET 内部 Redfish root 与 System，不发布库存或 Dashboard、不刷固件、不改 BIOS 变量、不含账号密码。System/CPU/Memory catalogue 来自当前主机 SMBIOS，暂只在内存构建。测试身份策略单独限定 .71 的 UUID 与公开 leaf 证书。

## 操作

由主代理确认 NetworkStack Disabled 后，从虚拟光驱 UEFI 启动。无需按键启动网络测试：启动器加载驻留驱动，然后只对匹配 BMC USB 控制器调用一次 ConnectController；库存核心只能经标准 DriverBinding.Start 进入。

完成后记录 `I5_BINDING_STARTS`、`I5_CORE_RUNS`、`I5_RESIDENT_STATE`、`I5_RESIDENT_RESULT`。正常只运行一次；日志中应有 `I5_BINDING_START_TPL=...0004`。按 C 导出全部二维码，V 查看文字，L 保存新 TXT（仅可写同包启动介质），Q/Q 返回固件。

## 限制范围

Supported 仅观察唯一 VID046b/PIDffb0、control interface0 和 data interface1，并确认两接口为同一物理 USB 路径。Start 创建并 BY_DRIVER 打开专属触发协议，不占用 USB_IO，避免阻挡真正的 RNDIS 驱动。

所有私有网络映像在 StartImage **之前**，先验证 LoadedImage 中固定 RVA 的 DriverBinding 数据、原始函数地址、版本、未初始化句柄；再把 Supported/Start/Stop 指针改成驻留白名单代理。USB层只允许这两个接口，后续网络层只允许该设备的物理 MAC/NII 父控制器，TCP6 一律拒绝。StartImage 返回后再次校验代理仍在。后续 BDS 不能通过这些私有模块连接其他 NIC。内部 MNP/IP4/TCP 子实例仍由原厂 ServiceBinding 创建和管理，不受错误的 USB 本体匹配限制。

原厂 NetworkStack enabled 分支和 Ip4Config2 不落盘隔离沿用 I5-A 已核验的私有 PE 副本；原始固件没有修改。原厂函数指针数据的临时替换另记于 `tests/scope-offsets.json`，不是对原始 PE 文件的额外磁盘补丁。

## 验证

- 160 个原厂/私有 enabled 门控机器码情形、6 个 Ip4Config2 无持久访问情形通过。
- 3,329 个 loader 断言覆盖预先代理、非目标句柄拒绝、TCP6拒绝、每级加载/启动失败、篡改前后检查、一次性策略。
- 229 个 USB/SNP/传输断言覆盖同设备两接口、错误/不完整路径、IPv4/IPv6 子句柄区分和清理失败保留。
- 25 个实际驻留 PE 场景执行 DriverEntry、真实 DriverBinding.Supported/Start 和当前 SMBIOS 解析；网络准备与TLS响应为替身。入口自身没有进行网络工作，TPL8拒绝工作，重复触发不重发。
- OVMF 从最终 ISO 加载真实驻留驱动，在无 BMC 时不调用核心，二维码完整还原并可 Q/Q 返回。

这不是默认 Disabled 的 .71 网络成功证据，也不是原生固件 BDS 时机证据。两项均需主代理后续实测。传输轮询预算和原厂同步调用无法抢占的限制同 I5-A：自己的超时轮询有限，但不能保证任意固件内部挂死都有硬总时限。

## 固件候选入口

`I5BNET.EFI` 为 EFI_BOOT_SERVICE_DRIVER，248,832 字节，SizeOfImage 2,965,504 字节。SHA-256：`7da5c6ca8bcc56c4cf2fc0ba17c614188877ef8dcb5e8135abc0c59659b30285`。

若只嵌入这一标准绑定注册入口，DEPEX 应允许早期安装 DriverBinding（TRUE/END，06 08），不等待 USB 或 TLS。实际工作延后至 BDS 连接匹配 BMC 接口时执行；不使用 ReadyToBoot 回调同步等待。PE32 section 最低为 248,836 字节，另计 FFS 头/UI/DEPEX/必要的节间对齐；FFS 末尾不可额外补齐节流。

Fast Boot 若不枚举/连接 BMC，则不会执行库存核心。原生 Supported 调用次序、control/data 两接口出现时机、SMBIOS 完整性以及实际 Start TPL 都仍需固件候选实测。不要据 RAM 包通过就标记原生自动发布完成。

只读状态协议 GUID：`7e06fa9a-532e-44c6-928a-cf19d2718e4b`，结构见 `source/i5.h`、version2。诊断可只读取日志/状态；`connect_probe` 专供 RAM 测试启动器，不需在正式驱动入口调用。
