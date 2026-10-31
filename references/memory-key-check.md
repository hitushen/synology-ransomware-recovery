# 重启与未重启：内存密钥检查

无论是否重启，先盘点可用密钥线索，再决定是否进入无密钥路线。不因“已重启”直接跳过旧内存、私有 key.sys / key / IV 或实际使用过的 swap。

## 按材料选择

| 状态与材料 | 处理 |
|---|---|
| 未重启且确认加密器存活 | 沿用用户提供的 SSH 或 Telnet，记录并暂停已确认进程、保全进程映射或整机内存；在独立分析机检查保存的副本 |
| 未重启但进程退出 | 保全仍可取得的 RAM 与实际使用过的 swap；不能保证已释放材料还在，记录采集范围与缺页 |
| 已重启且有旧 dump | 检查重启前的副本，记录采集时间和真实格式；正确保存的材料仍可用 |
| 已重启且有私有 key.sys / key / IV | 用 [密钥准备与副本解密](key-materials.md) 验证已有材料，不为此重新扫描进程 |
| 已重启，仅有新 RAM | 可对现有副本做有界结构检查，但它描述的是当前内存；通常不保留旧进程密钥，不能把阴性结果推广到旧会话 |
| 有实际 swap 残留 | 对独立保存的范围做 raw 字节结构检查；swap 可能未使用、被覆盖或没有完整材料，不从单独随机32字节猜 AES key |
| 无可用内存或密钥文件 | 明确记录“没有可检查材料”，继续副本、快照与旧块；不要记录成“内存检查证明没有密钥” |

现场采集见 [保全与内存](containment-memory.md)、[物理机内存](physical-memory_CN.md)。检测脚本只读保存的文件或映射集合，不连接 NAS、不读取 `/proc/PID/mem` 或磁盘设备、不执行 Solar 或恶意样本、不写回受灾卷。不要为取得内存重启设备。

## 统一检查入口

在技能根目录执行。输入必须是保存的副本；输出使用独立存储上的新私有目录。POSIX 下密钥文件使用0600，Windows 下另外核对目录 ACL。真实材料不贴聊天、不放命令行、不提交 GitHub。

保存的进程映射集合由 `capture_process_memory.py` 生成：

```sh
python -X utf8 scripts/memory_key_check.py --input saved-process --format process-maps --capture-origin not-rebooted --output new-private-key-check --progress-file new-memory-progress.json
```

重启前保存的 QEMU `pc.ram`，已核实与附带16GiB样本布局相符时：

```sh
python -X utf8 scripts/memory_key_check.py --input saved-pc.ram --format qemu --profile assets/libgld-802ac85d.json --capture-origin pre-reboot --output new-private-qemu-check --progress-file new-qemu-progress.json
```

保存的 LiME、raw / swap 副本或 ELF 文件可先按真实格式做字节结构检查：

```sh
python -X utf8 scripts/memory_key_check.py --input saved-memory.lime --format auto --capture-origin pre-reboot --output new-private-pattern-check --progress-file new-pattern-progress.json
```

`auto` 对目录选择进程映射，对文件识别 LiME / ELF 头，其他文件采用 raw 字节检查。**无法由扩展名自动证实 QEMU 地址布局；QEMU 页表提取必须显式选择 `--format qemu` 并核对 profile。** 不为让工具通过而只改 profile 的 RAM 长度、地址或 PCI hole。

## 各入口实际覆盖范围

- `process-maps`：检查已审阅样本摘要、代码签名、0x20模式、虚拟地址、所需映射 SHA 和不可读页，再取48字节 AES IV/key 候选。映射缺失、未知样本和不支持模式属于未能评估。
- `qemu`：复用已审阅的低1GiB虚拟地址、4KiB页表与 RAM/PCI-hole 映射，提取会话主材料和 ChaCha 对象候选。附带 profile 仅对应已核实样本与16GiB布局。
- `raw` / `lime` / `elf`：有界扫描相邻的 `AES_KEY=HEX64` 与 `AES_IV=HEX32` 文本，以及 key / nonce 重复的特定 ChaCha 状态；这不是通用 AES 密钥扩展搜索。LiME 先验证段头和物理范围，扫描不跨越段间地址空洞。ELF 只扫描容器字节并记录文件偏移，不声称已解析进程 VA。
- ChaCha key/nonce 或文件对象属于每文件材料，不能冒充会话 AES 主材料；本入口只将48字节 AES 候选送入现有副本解密器，其他材料保留待关联。

## 用独立密文验证候选

先检查目标副本的 footer 与样本兼容性，明确该会话 marker。有独立同版本原件 SHA-256 时：

```text
python -X utf8 scripts/memory_key_check.py --input saved-process --format process-maps --capture-origin pre-reboot --output new-private-verified-check --copy-root copies --input-copy copies/sample.L0CK3D --expected-marker 已审阅的8位十六进制标记 --expected-sha256 独立同版本原件的完整SHA256 --progress-file new-check-progress.json
```

没有历史摘要，但文件确为完整 TAR、单成员 gzip 或 tar.gz 时，可用 `--verify-archive tar`、`gzip` 或 `tar-gzip` 代替 `--expected-sha256`。完整格式通过只证明所列格式检查，不独立证明历史版本身份或业务可用性。未知格式继续使用对应的完整验证流程。

只提供 `--copy-root`、`--input-copy`、`--expected-marker` 时，做尾部一致性筛选，不解密全文，也不将结果记为已验证密钥。错误 IV 可能通过尾部 nonce 重复检查；没有实际加密正文的文件也不能用于证实 AES key / IV。

## 结果、私有报告与进度

| 状态 | 退出码 | 含义 |
|---|---:|---|
| `verified_for_file` | 0 | 至少一个候选通过指定副本的完整 SHA 或明确格式验证，报告注明证据级别；不宣称对所有文件或会话通用 |
| `not_assessed` | 1 | 格式/样本不适配、映射缺失、输入变化或检查失败，不能等同“没有密钥” |
| `not_found` | 2 | 本次提供的材料在列出的可执行检查中未找到候选；未检查布局、旧会话和未采集内存仍属未知 |
| `candidate_found` | 3 | 找到结构或尾部一致候选，但没有通过完整验证；保留候选，不统计为恢复成功 |

私有输出中 `memory-key-report.json` 记录采集来源声明、方法、范围、候选类型、去重数量、尾部筛选、逐候选验证及限制。密钥仅在私有 `.bin` 文件里；终端 stdout 输出状态与计数。失败的全文检查产物保留为明确标记的未验证副本，不覆盖源材料。

沿用 [实时进度查看器](live-progress.md)：

```sh
python -X utf8 scripts/recovery_progress.py watch new-memory-progress.json
```

字节扫描按实际读取量更新；页表或进程 VA 提取不虚构总量或 ETA。向用户汇报“检查了哪份内存、是什么格式、发现哪类候选、哪些通过何种验证”；不展示 key / IV，不因一次阴性结果无限重扫相同副本。
