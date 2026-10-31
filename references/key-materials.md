# 密钥材料分类与副本解密

记录来源、所属时间/会话、文件关联与格式，不在日志输出密钥字节。以下长度来自已验证的 `802ac85d…` 样本，不是所有 .L0CK3D 的通用格式。

| 材料 | 意义与处理 |
|---|---|
| AES key32 + IV16 | 会话主材料；解包同会话 footer 前 48 字节，再用每文件 ChaCha8 key/nonce 恢复正文 |
| 48 字节 raw | 仅来源格式证实为 **IV16 + AES key32** 时接受，不能猜 key32+IV16 或其他布局 |
| Solar `key.sys` | 本包静态字符串含 `AES_KEY=` 与 `AES_IV=`；准备脚本 `solar-key-sys` 严格读取完整字段，不凭扩展名认定格式 |
| 私有 JSON | 准备脚本只接受 `aes_key_hex` 与 `aes_iv_hex`，不猜别名、base64、大小端或默认 IV |
| 仅 AES key32／仅 IV16 | 不足以完整还原该样本文件密钥记录；不补零，不混入别会话材料 |
| 文件 key32 + nonce8 | 需证明与目标对应；使用 8 字节 nonce、64 位 counter、5MiB 调用与短块丢弃规则。现有 `decrypt_copy.py` 接受会话主材料，不能喂入此类型；需要单独副本适配与向量/真实文件验证 |
| RSA 私钥／其他家族材料 | 核对公钥配对、padding/记录布局；现成解密器不支持此入口 |
| 公共候选／别人的 key.sys | 仅候选；相同后缀、样本 SHA、marker 不证明同一 key/IV |
| RAM／进程 dump | 尚不是密钥；先核对格式/覆盖范围，再选离线提取器 |

## 准备主材料

材料放在源池之外的私有目录。JSON 必須包含 `aes_key_hex`（64 个 hex 字符）与 `aes_iv_hex`（32 个 hex 字符）；不要求将真实值贴入聊天。

```text
python scripts/prepare_session_key.py --input PRIVATE_JSON --format json --output NEW_MASTER_BIN
python scripts/prepare_session_key.py --input PRIVATE_KEY_SYS --format solar-key-sys --output NEW_MASTER_BIN
python scripts/prepare_session_key.py --input PRIVATE_RAW --format raw-iv-key --output NEW_MASTER_BIN
```

脚本检查长度/字符/重复字段/新输出，写出 48 字节 `IV16 + key32`，不输出内容。POSIX 输出模式为 0600；Windows 文件模式不能代替 ACL，确认目录仅当前用户可读。原密钥另留稳定备份，不覆盖已有文件。

## 验证后解密

1. 取得真正独立的密文副本，记录来源/复制摘要；输出位于独立池、新目录。检查大小与尾部完整性。
2. `inspect_footer.py --input-copy COPY` 记录 marker、0x20/0x21、模式、参数与范围。未知模式、追加日志、截断、重复 footer 单独分析，不能截掉尾部伪造成功。
3. 确认算法/尾部布局后**显式**传入已检查 marker：

```text
python scripts/decrypt_copy.py --copy-root COPY_DIR --input-copy COPY --master-file PRIVATE_MASTER_BIN --expected-marker HEX8 --output NEW_FILE
```

有同版本独立原件 SHA 时加 `--expected-sha256 HASH`；不同导出版本不能当同一原件。脚本创建新输出、不删源，拒绝已有输出、链接输入、尺寸/marker/crypto 模式不一致。

4. **重复 nonce 是过滤条件，不是认证。错误 AES IV 仍可能通过重复 nonce 检查，使文件 key 的前 16 字节错误。** 必须做完整 SHA 对照或完整格式校验，不能只看“成功”、magic 或预览。
5. 验证覆盖实际存在的全文件、首 1MiB、分段参数和不同会话，逐文件留收据。不存在的模式不假称覆盖。
6. 某会话失败就停止自动扩大，检查样本、IV、截断、混合会话、重复加密与计数器。保留密文并切换无密钥路线，无新证据不无限重试公共候选。

实现证据见 [逆向与解密](reverse-decrypt.md)。重启不改变已保存在外部的正确材料；扫描重启后的进程不能自动取得旧会话密钥。
