# R1 已知依赖问题 — 2026-09-28 更正

R1 构建脚本中名为 `PCI_ENUM` 的常量 `72338391-FB43-44A1-A9A2-64FEE1FC5E41` 被错误地解释为标准 PCI Enumeration Complete 协议。它实际只被确认是供体使用的通知 GUID，身份尚未核实。

标准 PI GUID 为 `30CFE3E7-3DE1-4586-BE20-DEABA1B3B793`，定义见 [EDK II 固定版本头文件](https://github.com/tianocore/edk2/blob/edk2-stable202502/MdePkg/Include/Protocol/PciEnumerationComplete.h)。

R1 将供体 GUID 作为 bootstrap 的硬性 DEPEX 依赖。此前模拟测试人为提供了它，因而**不能验证 HERO 是否会满足这个依赖并调度驱动**。对已提供 HERO 3001 的静态搜索没有找到此供体 GUID；它不能继续作为已成立的启动前提。后续版本需要修正依赖和通知策略，并核对实际调度。

用户新提交的 A1 日志确认实机已是 **3107**，且该供体 GUID 在诊断运行时未找到；A1 的对应标签同样有误。该日志未测试标准 PCI 枚举完成 GUID，也未执行 KCS。不能从它推出 R1 已启动或移植成功/失败。

历史 R1 CAP 仍保留供复核，SHA-256 不变：`36a5b7058b2522e1366ff51fe7d4ab6e86de9748d4cb24edfb5f203b8d53a282`。本次没有生成修正版 CAP。原先的结构和局部模拟结果仍是那些具体检查的结果，不能覆盖上述缺陷。

当前可执行的下一步是 `analysis/hero_ipmi_probe_a2` 中的 A2 诊断；详细结果与版本边界见其 `A1日志分析.md`。
