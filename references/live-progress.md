# 恢复实时进度

恢复任务应默认提供可观察的进度。仅创建技能不启动现场恢复或自动监控；实际执行已授权恢复时启动对应状态输出和查看器。

## 默认显示

- 终端与状态快照默认每2秒更新；工作完成、失败或中断立即更新。更新依赖实际处理回调，单次阻塞读取或长解码期间可能没有新字节，不伪造活动。
- 显示当前阶段/文件、已处理字节/已知总量、当前采样速度、预计剩余时间、阶段完成文件数、格式验证数、最终验收数和失败数。
- 字节百分比属于**当前阶段**：副本解密、导出落盘、归档源文件读取或历史 SHA 校验。归档校验按输入压缩字节计量，不混用解压后的成员字节。100%读取后仍可能在结束块、CRC、fsync 或业务验收失败。
- 总量未知则百分比/ETA 为未知，显示实际已处理量；遍历完成的文件数或失败数不能代替总恢复率。外部扫描工具无可核实总量时仅报告阶段/日志，不虚构密钥搜索百分比。
- 导出文件是候选，格式检查通过与历史原件匹配分别计数。最终 accepted 以实际验收收据为准；多个批次/共享范围不能简单累加导致重复统计。

## 已接入的脚本

以下命令在独立本机工作目录执行；`scripts/` 指本技能目录，示例文件名需替换成已授权的实际路径。每个任务使用新的进度 JSON，保存在源池之外，不与输入、恢复文件或其他 worker 共用路径。

```text
python scripts/decrypt_copy.py --copy-root COPY_DIR --input-copy COPY --master-file PRIVATE_MASTER --expected-marker HEX8 --output NEW_FILE --progress-file decrypt-progress.json
python scripts/c3r_local.py extract export.tar NEW_DIR --progress-file export-progress.json
python scripts/c3r_local.py validate NEW_DIR --progress-file validate-progress.json
python scripts/verify_backup.py NEW_FILE.tar.gz --progress-file archive-progress.json
```

均支持 `--progress-interval 2`，进度写 stderr，不污染 stdout 的 JSON、归档或数据管道。不需要新第三方库。脚本内部作为库使用时，通过可选 `progress` 对象接入；未接入的旧调用保留原来的输出行为。

extract 可在确知候选文件总载荷时加 `--total-bytes N`；不把 TAR 容器大小当载荷总量。进度不计 `_c3r_manifest.jsonl` 的元数据字节或文件数。validate 为多进程文件检查，完成一个文件后更新计数；单个大文件的 SHA/解码正在运行时不能据零增量认定停机。

多进程校验按实际完成顺序更新，不等待首个大文件完成才显示后面的结果。阶段文件/格式检查数以候选检查次数计，最终验收按源文件身份去重，prev/next 两个匹配候选不会计为两份原件。验收总账仍须跨批次去重。

## 终端与实时网页

另开本地终端读取多个任务快照：

```text
python scripts/recovery_progress.py watch decrypt-progress.json export-progress.json archive-progress.json --interval 2
python scripts/recovery_progress.py watch export-progress.json archive-progress.json --html NEW_LIVE_PROGRESS.html
```

查看器每2秒重读状态；交互终端刷新显示，非交互终端输出普通文本。`--html` 创建本地网页，打开它即可自动刷新；查看器运行时持续生成最新内容。网页无远程脚本、网络上报或真实密钥，动态文件名经过 HTML 转义。关闭查看器不终止恢复任务；网页标出真实数据更新时间（北京时间，快照内部保存 UTC），可辨认陈旧数据。输入快照未生成时显示等待，不报假失败。

网页和进度 JSON 都要求新文件名，避免覆盖现有数据。断点恢复用新 task_id/状态文件；统一调度通过源身份和验收总账去重，而不是把本轮阶段完成数加到旧百分比。Ctrl+C 后相关 CLI 记录 interrupted，失败不计入 accepted。

## 自定义 Drive／旧块／采集循环

在**独立主机**的已审阅执行器中使用公共类，无需在受灾卷部署监控：

```python
from recovery_progress import Progress
progress = Progress('Drive副本导出', 'new-task-progress.json', total_bytes=verified_expected_size)
# 每次完成实际写入后：progress.advance(len(block), current_file=display_name)
# 文件完整落盘后：progress.file_done()  # 此时仍为候选
# 独立回读、源映射/CRC和相应完整格式验收后由调度登记 accepted。
# 本阶段正常结束：progress.finish('candidate')
# 失败/中断：progress.fail(interrupted=True)
```

总量来自已验证的源计划/盘点，未知则用 None；库不查源盘、不重复扫 NAS。`ProgressReader` 可测量读流。显示/状态写入错误是辅助监控错误，不改变恢复字节、删恢复结果或伪造验收；初始状态文件冲突则直接拒绝，避免覆盖数据。

在聊天中每30–60秒按实际快照简述当前阶段、处理量、速度及剩余不确定性；重要失败、需要用户选择或完成立即报告。不能用查看器每次刷新时间冒充后台任务的新进度，也不能保证无数据的外部工具持续提供字节百分比。
