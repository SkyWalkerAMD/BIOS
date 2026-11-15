W790E-SAGE SE 1904 的原始 DxeCore 支持并在 ExitBootServices 路径中调用 `EFI_EVENT_GROUP_BEFORE_EXIT_BOOT_SERVICES`。结论来自原模块机器码和局部原生执行模拟，不依赖 OVMF，也不是实机运行记录。

输入模块 SHA-256 为 `d8684ae913fe44bfcb950c0635299465d7813b1f60407a733f7cce34e50f584d`，与原始 CAP 解压模块逐字节一致；原 CAP 固定为 `aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3`。

[EDK2 官方定义](https://raw.githubusercontent.com/tianocore/edk2/master/MdePkg/Include/Guid/EventGroup.h)中的 Before GUID 是 `8BE0E274-3970-4B44-80C5-1AB9502F3BFC`。原 Core 的 `0x15AF0` 与 `0x15C20` 均包含它。Boot Services 表 `0x15E90` 的 ExitBootServices 槽指向 `0x25A0`，CreateEventEx 槽指向 `0x9328`。

原生流程存在一个重要细节：首次 ExitBootServices 会**两次广播同一个 Before 组**，调用点是 `0x25D7`、`0x25E3`，随后停止 timer、调用 Exit 组，最后在 `0x2603` 清除一次性标志。广播函数 `0x9280` 比较事件记录中完整 16 字节 GUID，再通过原生通知队列和 TPL 分派，在 `0xCD4C` 调用已注册的回调。

这并非每次调用都无条件广播：`0x15CC0` 初值为 1，仅首次路径执行。MapKey 的早期比较不会阻止首次广播。错误 MapKey 可以在 Before 和 Exit 回调已完成后才返回 `EFI_INVALID_PARAMETER`；失败路径不恢复一次性标志，后续正确 MapKey 重试可以成功，却不再通知 Before 或 Exit 组。[UEFI Boot Services 规范](https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html)允许 ExitBootServices 首次失败前发生部分关闭；此处的具体两次 Before 行为由原 ASUS 模块证实。

局部 Unicorn 模拟执行了原始 CreateEventEx、广播、队列、TPL 分派和 ExitBootServices 分支。15 次注册和 5 个退出/重试案例均满足断言：TPL 16/8 的两个 Before 观察回调各执行两次，Exit 一次；错误 MapKey 追加失败组回调，重试不再执行 Before/Exit；无关 GUID 回调从未执行。分配器、CPU/timer 协议、状态报告、最终 CRC 和观察回调是本地测试替身；未执行候选驱动、未连接设备。

对修复的直接要求：Before 清理必须幂等。即使第一次 ExitBootServices 失败返回，RuntimeServices 指针也应保持已还原，驱动不得重新安装已退役的挂钩，更不能期待下一次 ExitBootServices 再通知 Before。候选实现自身是否满足这些条件，仍应由独立的候选驱动测试确认。

证据与逐指令反汇编保存在 `before_exit_core_support.json`，可运行同目录 `before_exit_core_support.py` 复核。原始固件、生产代码和发布包均未修改。
