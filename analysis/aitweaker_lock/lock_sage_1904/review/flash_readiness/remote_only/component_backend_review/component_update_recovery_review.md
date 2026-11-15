离线检查已确认：进入更新及 Prepare 会修改状态，不能用作只读探测。Prepare 会切换 GPIO15、装载 host_spi_flash_hw，并清理暂存文件；只在这些用户态函数内未见提前 erase/flash 调用，不代表已经证明所有下层动作都无写入。

命名为 BIOS backup 的函数仅将 recovery_bios.bin_tmp 改名为 recovery_bios.bin；已发现的暂存文件来源是在成功刷写验证后移动 /var/bios.bin。另有从 MTD 把指定 Non Program Block 区段复制进待刷映像的保留逻辑，但都不是刷写前全 SPI 导出。

确有原生 recovery worker 会把 recovery_bios.bin 写入 SPI。这说明实现中存在恢复写入逻辑；尚未证明实机有这个文件、覆盖范围充分、存在厂商支持的公开入口，或任何无法 POST 的损坏都可远程恢复。正常版本读取还会从现有 SPI 的 48 MiB 位置搜索 $BOOTEFI$ 元数据。

原版 CAP 与 EXP02 的验签结果继续沿用既有独立数学证据：EXP02 固件签名仍失败。没有调用 BMC、进入更新模式、上传、刷写或绕过校验。

精确库哈希、原生地址、调用点、字串重定位及带注释反编译分别见 component_update_recovery_review.json、elf_callsite_evidence.json 与 annotated_decompile/。Ghidra 地址比 ELF 链接地址多 0x10000；没有宣称这些地址是实机运行地址。
