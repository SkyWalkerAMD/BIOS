# HERO FW ID I2 只读固件身份采集镜像

文件：`HERO-FW-ID-I2-READONLY.iso`

SHA256：`c48310c587ba1e1db6cf59dcafd18bb787b2634c4c51757c82124d3aa14ad50c`

此镜像只采集当前加载映像和固件卷中 R2／P5／P6 文件的身份信息，不运行传感器初始化，不写 BIOS 或 BMC 配置。它与 I1 SMBIOS 镜像分别保存。

## 操作

1. 挂载本 ISO 并重新从虚拟光驱启动，确认标题是 `HERO FW ID I2 - FIRST TEXT / WAITING FOR F`。只更换挂载文件而不重新启动，可能仍显示上一份工具。
2. 按 **F** 采集一次。出现 `CAPTURE_READY` 或 `CAPTURE_INCOMPLETE` 都可继续导出；后者意味着部分查询未完成，日志仍有价值。
3. 按 **C** 显示二维码，用 N／Enter 翻页，保存每一页截图；按 **R** 可查看文字。Esc 关闭日志查看器。
4. 回到工具主界面后按 **Q，再按一次 Q** 返回固件。Enter／Esc 不会直接退出主界面。
5. 若使用本目录 `USB` 内的文件从可写 U 盘启动，按 **L** 可保存 `FID000.TXT` 等新文件。此功能只接受带本工具标记的启动卷；虚拟光驱的只读 ISO 使用二维码方式导出。

二维码还原：`decode_captures.py 截图目录 --output FW-ID-I2.TXT`。还原器检查页数、分片 CRC、整份 CRC 和 I2 日志头尾，不会执行二维码内容。

## 结果含义

- `FP_R2_FV_FILES` 大于零：本次可见固件卷中确有目标 R2 文件。
- `FP_R2_LOADED_MATCHES` 大于零：当前发现 R2 的已加载映像；不保证初始化成功。
- `FP_FV_PE_BYTES/CRC32`：可与上一层 `known-pe-images.json` 对比原始 PE。已加载内存 CRC 含重定位和可变内容，不能这样直接比较。
- 所有匹配为零不等于已证明刷的是 RC2；读取范围、协议公开情况和日志中的不完整状态需要一起判断。

## 验证

- `verification.json`：实际交付 EFI 在 Unicorn 中执行的 12 个启动／读取／退出／可选文件保存场景，以及二维码逐字节还原和图片扫码，共 14 项通过。默认采集／查看／退出路径没有写入服务调用。
- `vm-verification.json`：相同 ISO 在本地 OVMF 光驱启动通过，真实固件卷枚举与查询完成，二维码截图解码一致，双 Q 退出通过。
- 这些是离线／OVMF 证据，不是 Z790 HERO 的实机采集结果。OVMF 本身没有 R2/P5；找到目标文件后的 ReadSection 成功分支通过模拟接口测试。
