# 共用源码

尚不能仅凭路径归属单一主板的 Ai Tweaker 探针、模拟器、分析工具和共用代码。

当前分类含 **90 个原始源码文件**。

**验证状态：** 共用文件保留原始来源路径；分类主要依据工程目录归属，没有按文件中的偶然板型引用重分代码。

## 源码入口

- [analysis/IPMI移植分析.md](analysis/IPMI移植分析.md)
- [analysis/aitweaker_lock/code_index.py](analysis/aitweaker_lock/code_index.py)
- [analysis/aitweaker_lock/deliver.py](analysis/aitweaker_lock/deliver.py)
- [analysis/aitweaker_lock/delivery_dual_mode_20261102](analysis/aitweaker_lock/delivery_dual_mode_20261102/)：19 个文件。
- [analysis/aitweaker_lock/inspect_forms.py](analysis/aitweaker_lock/inspect_forms.py)
- [analysis/aitweaker_lock/inspect_setup.py](analysis/aitweaker_lock/inspect_setup.py)
- [analysis/aitweaker_lock/probe](analysis/aitweaker_lock/probe/)：7 个文件。
- [analysis/aitweaker_lock/probe_p2](analysis/aitweaker_lock/probe_p2/)：10 个文件。
- [analysis/aitweaker_lock/probe_p3_kvm](analysis/aitweaker_lock/probe_p3_kvm/)：19 个文件。
- [analysis/aitweaker_lock/simulation_extra_20261015](analysis/aitweaker_lock/simulation_extra_20261015/)：4 个文件。
- [analysis/aitweaker_lock/uefi_vm_20261015](analysis/aitweaker_lock/uefi_vm_20261015/)：6 个文件。
- [analysis/bmc_arm_inspect.py](analysis/bmc_arm_inspect.py)
- [analysis/compare.py](analysis/compare.py)
- [analysis/disassemble.py](analysis/disassemble.py)
- [analysis/fetch_pydeps.py](analysis/fetch_pydeps.py)
- [analysis/fetch_support.py](analysis/fetch_support.py)
- [analysis/fetch_uefi_probe_tools.py](analysis/fetch_uefi_probe_tools.py)
- [analysis/inspect_modules.py](analysis/inspect_modules.py)
- [analysis/inventory.py](analysis/inventory.py)
- [analysis/package_analysis.py](analysis/package_analysis.py)
- [analysis/porting_bundle](analysis/porting_bundle/)：1 个文件。
- [analysis/prepare_porting_bundle.py](analysis/prepare_porting_bundle.py)
- [analysis/query.py](analysis/query.py)
- [analysis/semantic_diff.py](analysis/semantic_diff.py)
- [analysis/setup_layout.py](analysis/setup_layout.py)
- [analysis/show_asm.py](analysis/show_asm.py)
- [analysis/structures](analysis/structures/)：1 个文件。
- [analysis/verify_bmc_fan_handler.py](analysis/verify_bmc_fan_handler.py)
- [analysis/volume_layout.py](analysis/volume_layout.py)
- [analysis/workstation_20261008](analysis/workstation_20261008/)：2 个文件。

## 目录与构建

为分类浏览，原始源码放在当前板型目录下。构建脚本中的原始相对路径未作批量改写。使用仓库根目录的 `restore-source-layout.py` 可按清单恢复原 `analysis/` 布局；所需固件、第三方工具和被排除文件仍须从本地完整工程补齐。
