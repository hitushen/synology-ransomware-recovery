# 第三方来源与许可范围

本项目有权授权的原创内容与修改采用 [MIT 许可证](LICENSE)。第三方内容保留各自版权与许可。记录时间：2026-10-31。

## crt106 / Btrfs 恢复工具

来源：[crt106/c3rb3r-btrfs-recovery](https://github.com/crt106/c3rb3r-btrfs-recovery)。上游采用 MIT，版权为 `Copyright (c) 2026 crt106`；原许可证保存在 [licenses/crt106-MIT.txt](licenses/crt106-MIT.txt)。

对应资源为 `scripts/c3r_btrfs.py`、`scripts/c3r_local.py`、`scripts/mkjob.py` 及 Btrfs 原理、兼容性、常见问题和报告参考。集成版增加覆盖保护、独立回读 SHA、验证分类、实时进度与候选验收去重；上游与集成版摘要见 `assets/tool-sources.json`。

## soimy / 救援资源

来源：[soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue)。包含现场保全、内存提取、副本解密等脚本、样本配置与说明的适配。原始贡献版权归上游作者。

本次检查未发现明确许可证（仓库 API 的 license 为 null，license endpoint 返回404）。这部分第三方原始内容的许可状态保持未确认，不纳入本项目 MIT 的授权范围；本项目自行编写且有权授权的修改按 MIT 提供。

## Solar / 官方恢复二进制

发布团队：Solar 应急响应团队（州弟学安全、CHQ）。来源：[原文](https://mp.weixin.qq.com/s/MhVPW1c1n3FcubvkwGrzkA)与[官方工具页](https://xn--vvr70uba61n.com/tools/S28L0c-111)，编号 `S28L0c-111`。

分发包包含官方工具 [assets/solar/c3rb3r_memscan.sys](assets/solar/c3rb3r_memscan.sys)，741328字节，SHA-256 为 `6376fb498cddc54220ae3381fe927a26eaa82c70f0f5647c72b057b7d904a6c9`。来源、下载时间和验证记录见 [来源收据](assets/solar/provenance.json)。

二进制版权归原作者；官方再分发许可证尚未查明，本项目不将其重新授权为 MIT。随包集成不改变其来源与许可状态。已核对来源、哈希和静态结构，未执行或实机验收；使用说明见 [Solar 工具接入](references/solar-tool.md)。

## 流程、格式与测试参考

- [Benjamin-zlt/c3rb3r-baremetal-rescue](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue)：物理 DSM 内存保全流程参考，没有附带其完整工具集或据此宣称已实机验证。
- [Microsoft/AVML](https://github.com/microsoft/avml)：可选物理内存采集工具参考，不附其发行包。
- [504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME)：可选采集及段头格式参考，不附其内核模块；`inspect_lime.py` 检查对应格式。
- [Botan ChaCha vectors](https://github.com/randombit/botan/blob/master/src/tests/data/stream/chacha.vec)：公开算法测试向量参考，未集成 Botan 库。
- [CGSecurity / TestDisk 与 PhotoRec](https://www.cgsecurity.org/wiki/TestDisk)：独立镜像上的历史文件系统与文件特征恢复参考，不附其程序。
- [GNU ddrescue](https://www.gnu.org/software/ddrescue/)：有物理读错误时的镜像采集参考，不附其程序。

完整贡献说明见 [README 的致谢](README.md#致谢)。分发包不包含真实密钥、内存转储、恶意样本、用户恢复文件、私人日志或现场凭据。
