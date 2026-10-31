# Solar 公号恢复工具接入

来源：[原文](https://mp.weixin.qq.com/s/MhVPW1c1n3FcubvkwGrzkA)，标题《【勒索解密】群晖NAS .L0CK3D勒索病毒特定条件下可解密（附解密工具）》；作者 Solar 应急响应团队（州弟学安全、CHQ）。2026-10-31 已读取正文与官方工具页。

官方入口：[工具中心](https://xn--vvr70uba61n.com/tools)、[本工具 S28L0c-111](https://xn--vvr70uba61n.com/tools/S28L0c-111)、[备用中心](https://xn--vvr70uba61n.cn/tools.html)。以官网实际版本为准，备用站链接可能有时效签名。原文公开解压密码为 `solarsecurity`，不是受害者密钥。

## 附带材料与验证状态

- `assets/solar/c3rb3r_memscan.sys`，741328 字节，ELF64 little-endian x86-64；安装版与 GitHub 分发包均附程序。
- SHA-256：`6376fb498cddc54220ae3381fe927a26eaa82c70f0f5647c72b057b7d904a6c9`。
- 官网 ZIP SHA-256：`8904c90c2f1f2122499cbb9dba4d1b88d619d2112833cae6e2f59b2cbd082c9a`。完整来源收据见 `assets/solar/provenance.json`。
- 已检查来源链、归档密码、ELF 头与帮助字符串；**未执行二进制，未验证运行时兼容性或 dump 格式。** 自算 SHA 是下载一致性记录，不是发布者签名、安全审计或实机成功证明。
- 安装版与 GitHub 分发包均附官方二进制。其版权及许可状态见 [第三方说明](../THIRD_PARTY_NOTICES.md)，本项目 MIT 范围限于有权授权的原创贡献与修改。真实 `key.sys` 不放进技能包。

## 兼容性与副作用

原文样本 SHA 为 `802ac85d19dc6db2b1849bb3499877280544d04a0ae94d4c408b6c321669903d`，固定全局指针 VA 为 `0x5427f8`。进程名可修改；pgrep 只是线索，需要路径、摘要、启动时间和状态佐证。ARM、不同 ELF、PIE 或未知 footer 不能直接套地址。

工具会生成敏感 `key.sys`，可能打印 key/IV。原文说 key 文件在工具所在目录生成，故将工具复制到可信的私有工作目录再用，确认目录在源池之外。现场如需落地，只能用已核实独立挂载或受控 tmpfs；tmpfs 也会改变内存，尽量先采集。`.sys` 是 Linux 程序命名，不是 Windows 驱动，也不是所有变种都跳过加密的保证。

**默认解密成功会删密文**，`--force` 可覆盖输出及 key.sys。所有解密带 `--keep-source`，不以 `--force` 绕过冲突；只处理独立副本，不在原 `/volume*` 目录执行。不要再次运行勒索程序。

## 三种入口

下列参数来自文章或本包静态帮助字符串。先在可信 Linux x86-64 独立环境核对实际 `--help`，不要仅为帮助在受灾机执行。

### 未重启，确认进程存活

先暂停已确认加密进程并保全内存。本包静态帮助还有 `--pid` 与可重复 `--file`：

```sh
./c3rb3r_memscan.sys --pid PID --file INDEPENDENT_COPY.L0CK3D
```

仅在已有授权和匹配样本上以必要权限读取内存。key 输出写私有日志，避免回传聊天。`UNVERIFIED_POINTER` 为未验证候选；结构验证也不能代替全文验证。

### 已重启，保存了旧转储

本包静态帮助含：

```sh
./c3rb3r_memscan.sys --dump-input SAVED_DUMP --file INDEPENDENT_COPY.L0CK3D
```

`--pid` 与 `--dump-input` 互斥。参数存在**不证明**兼容 LiME、ELF core、QEMU pc.ram、物理 raw 或多段进程 dump。确认映射、VA/偏移和完整性后在副本测试并记录拒绝；未知格式优先用对应的 Python 提取器或适配代码，不能盲扫当前新内存。

### 已有 AES key + IV／key.sys

文章副本解密示例：

```sh
./c3rb3r_memscan.sys --decrypt INDEPENDENT_COPY.L0CK3D --keep-source
```

文章也给出 `--aes-key HEX64 --aes-iv HEX32`；真实材料在 argv/日志会暴露，默认使用私有 key 文件，或 [准备脚本](../scripts/prepare_session_key.py) 转成 raw48 再用 `decrypt_copy.py`。没有 key.sys 时 `--decrypt` 可能在线扫描，离线任务先确认材料存在。

先验证单文件，再扩大目录，仍保留 `--keep-source`。输出在输入附近，副本目录必须独立且容纳密文+输出。完整归档/数据库/解码验收后逐项登记，目录成功数不能代替验收。

原文速度、受害版本与入口描述为作者观测，不是通用时间窗口或本机漏洞结论。恢复不等待完整溯源；实际补丁与入侵入口另以证据核对。
