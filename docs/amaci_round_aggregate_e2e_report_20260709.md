# AMACI SP1 Aggregate Proof E2E 报告 2026-07-09

## 1. 结论

本次 E2E 在本地 `dorad` CosmWasm devnet 上，验证了一轮真实的 `2-1-1-5` AMACI round 的 aggregate proof 路径。

最终结果：

```text
round complete: true
verified proofs: 4
completed.process_deactivate: 1
completed.add_new_key: 1
completed.process_messages: 1
completed.tally: 2
```

和非 aggregate 路径相比：

```text
non-aggregate proof verify tx count: 5
aggregate proof verify tx count: 4
proof verify gas saved: 20,334,849
proof verify gas saved ratio: 19.997%
proof verify estimated DORA saved: 0.203348490 DORA
```

本轮 five-signup 的 `processMessages` 只有 1 个 child proof，所以 processMessages aggregate 主要验证路径正确；实际 gas 节省来自 `tally0 + tally1 -> tally aggregate`。更大规模 round 中，如果 `processMessages_*` 和 `tally_*` 都产生多批 proof，aggregate 收益会更明显。

## 2. 测试范围

本次测试覆盖：

- SP1 aggregate proof artifacts 由高性能机器生成；
- 本地将 aggregate artifacts 组装为 CosmWasm execute msg；
- CosmWasm round 合约接收 aggregate proof；
- 合约验证 aggregate compressed proof；
- 合约根据 aggregate public output 的 `child_count` 推进 round stage；
- 原始 child proof 路径仍然保留，`processDeactivate` 和 `addNewKey` 继续走原路径；
- 最终 round state 完成。

本次没有改变 AMACI 协议业务语义：

- child proof 仍然由原始 SP1 AMACI guest 生成；
- aggregate proof 只做递归验证和 public output 链接检查；
- processMessages / tally 的 state transition 和 commitment 链路仍在 child proof 中约束；
- CosmWasm 合约只验证 aggregate proof 和 round stage 顺序。

## 3. 实现入口

| 模块 | 文件 | 作用 |
| --- | --- | --- |
| aggregate public output 检查 | [`aggregate.rs`](../crates/proof-core/src/aggregate.rs) | 检查 processMessages / tally child public output 链接，并生成 aggregate public output。 |
| SP1 aggregate guest | [`proof-sp1-aggregate-program/src/main.rs`](../crates/proof-sp1-aggregate-program/src/main.rs) | 在 zkVM 内验证 child proofs，并 commit aggregate public output。 |
| SP1 aggregate host | [`proof-sp1-aggregate-host/src/main.rs`](../crates/proof-sp1-aggregate-host/src/main.rs) | 读取 child proof/msg，生成 aggregate compressed proof artifacts。 |
| CosmWasm round 合约 | [`contract.rs`](../crates/cosmwasm-amaci-round/src/contract.rs) | 新增 `verify_compressed_aggregate_stage`，验证 aggregate proof 并按 `child_count` 推进 round。 |
| 合约消息类型 | [`msg.rs`](../crates/cosmwasm-amaci-round/src/msg.rs) | 新增 `VerifyCompressedAggregateStage`。 |
| aggregate msg 生成 | [`make_cosmwasm_sp1_aggregate_msg.sh`](../scripts/make_cosmwasm_sp1_aggregate_msg.sh) | 将 aggregate proof/public/vkey 组装成 CosmWasm execute msg。 |
| E2E manifest | [`round-e2e.aggregate.example.json`](../fixtures/round-e2e.aggregate.example.json) | 本次 aggregate round E2E 输入配置。 |
| E2E runner | [`run_cosmwasm_round_e2e.mjs`](../scripts/run_cosmwasm_round_e2e.mjs) | 同时支持 `verify_compressed` 和 `verify_compressed_aggregate` msg。 |

## 4. Round 流程

本轮 round 仍然是 `2-1-1-5` five-signup fixture：

```text
processDeactivate -> addNewKey -> processMessages -> tally0 -> tally1
```

aggregate 后，链上提交顺序变成：

```text
processDeactivate proof
addNewKey proof
processMessages aggregate proof
tally aggregate proof
```

其中：

```text
processMessages aggregate child_count = 1
tally aggregate child_count = 2
```

合约 round plan 不变：

```json
{
  "process_deactivate": 1,
  "add_new_key": 1,
  "process_messages": 1,
  "tally": 2
}
```

也就是说，合约仍认为业务 round 需要 2 个 tally batch；只是链上通过一个 `tally aggregate proof` 一次推进 2 个 tally child proof。

## 5. Aggregate Proof Artifacts

高性能机器生成并同步到本地的 aggregate artifacts：

| Artifact | Bytes |
| --- | ---: |
| `sp1-proofs/five-signup-process-messages.aggregate.sp1-compressed-proof.bytes` | 1,272,546 |
| `sp1-proofs/five-signup-process-messages.aggregate.public.bin` | 301 |
| `sp1-proofs/five-signup-process-messages.aggregate.vkey.bin` | 32 |
| `sp1-proofs/five-signup-tally.aggregate.sp1-compressed-proof.bytes` | 1,272,546 |
| `sp1-proofs/five-signup-tally.aggregate.public.bin` | 149 |
| `sp1-proofs/five-signup-tally.aggregate.vkey.bin` | 32 |

组装后的 CosmWasm execute msg：

| Execute msg | Bytes |
| --- | ---: |
| `sp1-proofs/five-signup-process-messages.aggregate.verify-compressed-aggregate.msg.json` | 1,697,255 |
| `sp1-proofs/five-signup-tally.aggregate.verify-compressed-aggregate.msg.json` | 1,697,051 |

高性能机器上本次 aggregate proving 结果：

| Aggregate stage | child_count | raw proof bytes | public bytes | max RSS KB |
| --- | ---: | ---: | ---: | ---: |
| `processMessagesAggregate` | 1 | 1,272,546 | 301 | 18,352,392 |
| `tallyAggregate` | 2 | 1,272,546 | 149 | 24,178,404 |

## 6. 本地执行命令

先组装 aggregate execute msg：

```bash
scripts/make_cosmwasm_sp1_aggregate_msg.sh process-messages \
  > sp1-proofs/five-signup-process-messages.aggregate.verify-compressed-aggregate.msg.json

scripts/make_cosmwasm_sp1_aggregate_msg.sh tally \
  > sp1-proofs/five-signup-tally.aggregate.verify-compressed-aggregate.msg.json
```

构建合约：

```bash
npm run build:round-contract
```

执行 E2E：

```bash
node scripts/run_cosmwasm_round_e2e.mjs \
  --manifest fixtures/round-e2e.aggregate.example.json
```

完整机器可读结果在：

```text
round-e2e-results/20260709124729/summary.json
round-e2e-results/20260709124729/summary.md
```

## 7. Aggregate 链上执行结果

本次 aggregate E2E：

```text
chain: zkvm-amaci-devnet
contract: dora10qt8wg0n7z740ssvf3urmvgtjhxpyp74hxqvqt7z226gykuus7eqpt9lpd
signer: dora1y3uljxavztyw7tvlj3agacaja9scj5x0pkk5ml
cost gas price: 10000000000 peaka/gas
total estimated cost: 0.850046240 DORA
```

最终 round state：

```json
{
  "round_id": "five-signup-2-1-1-5-aggregate",
  "expected": {
    "process_deactivate": 1,
    "add_new_key": 1,
    "process_messages": 1,
    "tally": 2
  },
  "completed": {
    "process_deactivate": 1,
    "add_new_key": 1,
    "process_messages": 1,
    "tally": 2
  },
  "next_stage": null,
  "is_complete": true,
  "verified_proofs": 4
}
```

交易明细：

| 步骤 | 高度 | Gas wanted | Gas used | 估算 DORA | 交易哈希 |
| --- | ---: | ---: | ---: | ---: | --- |
| store_code | 64593 | 3,855,369 | 3,506,491 | 0.035064910 | `02CD893B3947254FF4B811C3D61B9F3F25F3A04742FFAD1CE3842EE7589DD6AF` |
| instantiate_round | 64594 | 198,424 | 143,335 | 0.001433350 | `6B43D64C003BAFD85339F95839605A32B1F88212BC5759E64B9E5734466479ED` |
| process_deactivate | 64595 | 300,000,000 | 20,339,100 | 0.203391000 | `5D9AAA547107634A72A4B39813DA40239C8FBAA0B90C11A91270169FB50BB276` |
| add_new_key | 64596 | 300,000,000 | 20,339,391 | 0.203393910 | `CED2DF6C2DFEC4B411CEA182CAAE4F13905C4A15373CC2400155507443AA48C1` |
| process_messages_aggregate | 64597 | 300,000,000 | 20,339,341 | 0.203393410 | `0F6E2E241232FA24F2E1DAF9BDB3E6D9037631B6DE8BC5027895B14D52D9A2F8` |
| tally_aggregate | 64598 | 300,000,000 | 20,336,966 | 0.203369660 | `9971815BA83143CFFBA00CAA76C0195C579BE3307776E8E2A90F878DD723BA68` |

只计算 4 个 proof verify，不包含 store code 和 instantiate：

```text
gas: 81,354,798
estimated cost: 0.813547980 DORA
```

## 8. Non-Aggregate 基准

用于对比的 non-aggregate 基准来自：

```text
round-e2e-results/20260705102941/summary.json
docs/amaci_round_pqc_e2e_report_20260705.md
```

该路径逐个验证 5 个 SP1 compressed proof：

```text
processDeactivate proof
addNewKey proof
processMessagesFull proof
tally0 proof
tally1 proof
```

最终 round state：

```json
{
  "completed": {
    "process_deactivate": 1,
    "add_new_key": 1,
    "process_messages": 1,
    "tally": 2
  },
  "next_stage": null,
  "is_complete": true,
  "verified_proofs": 5
}
```

non-aggregate 交易明细，统一按 `10000000000 peaka/gas` 估算：

| 步骤 | 高度 | Gas wanted | Gas used | 估算 DORA | 交易哈希 |
| --- | ---: | ---: | ---: | ---: | --- |
| store_code | 35771 | 3,822,887 | 3,476,962 | 0.034769620 | `481AC8296927809B6C4A4C6AB2FEC8182642A8BCCF79D3087DC806017D35469F` |
| instantiate_round | 35772 | 196,866 | 142,222 | 0.001422220 | `939011C87A559117D70B1E3D819D96524D0372F22A0546E35E3636F9DC42F687` |
| process_deactivate | 35773 | 300,000,000 | 20,338,714 | 0.203387140 | `B1F42AD9411C95B0CDCF56678606726D3F8AB58270548312E84BB90E11177EAF` |
| add_new_key | 35774 | 300,000,000 | 20,339,006 | 0.203390060 | `836837D9472FA897841C42E6BCC7644E0A7BE7892C8B9120BD2B59B817F4080A` |
| process_messages_full | 35775 | 300,000,000 | 20,338,660 | 0.203386600 | `D4BD968CF1066CCC4DBB62B2F33679C7BFEE39CD4DA3B51B5CEA3A425B671F80` |
| tally_0 | 35776 | 300,000,000 | 20,336,637 | 0.203366370 | `17A727E7034FCB9BAF2D1FA5C7E0032D4DDFD4270F6038F56361FE1B49B839AE` |
| tally_1 | 35777 | 300,000,000 | 20,336,630 | 0.203366300 | `3068FC3CBD5542AF23871F3221DD94E011E70C0878D7BDCD2F8DCD9B63EC6ACB` |

只计算 5 个 proof verify，不包含 store code 和 instantiate：

```text
gas: 101,689,647
estimated cost: 1.016896470 DORA
```

## 9. Aggregate vs Non-Aggregate 对比

| 指标 | Non-aggregate | Aggregate | 差值 |
| --- | ---: | ---: | ---: |
| 链上 verify proof 交易数 | 5 | 4 | -1 |
| `verified_proofs` | 5 | 4 | -1 |
| round 是否完成 | true | true | 无变化 |
| proof verify gas | 101,689,647 | 81,354,798 | -20,334,849 |
| proof verify 估算 DORA | 1.016896470 | 0.813547980 | -0.203348490 |
| proof verify gas 节省比例 | - | - | 19.997% |
| 总 gas，含 store/instantiate | 105,308,831 | 85,004,624 | -20,304,207 |
| 总估算 DORA，含 store/instantiate | 1.053088310 | 0.850046240 | -0.203042070 |

这次 aggregate 合约 wasm 比旧版合约稍大，所以 `store_code` gas 从 `3,476,962` 增加到 `3,506,491`。因此总成本节省略小于单纯 proof verify 节省。生产环境中合约只会部署一次，更应关注 proof verify gas。

## 10. 如何理解这次收益

本轮 five-signup 规模较小：

```text
processMessages child_count = 1
tally child_count = 2
```

因此 aggregate 后，链上 proof verify 从 5 次减少到 4 次。节省大约等于少验证 1 个 compressed proof 的成本。

更大规模 round 中，收益会随可聚合 proof 数量线性放大。例如：

```text
非 aggregate:
processDeactivate + addNewKey + 3 processMessages + 4 tally = 9 verify tx

aggregate:
processDeactivate + addNewKey + 1 processMessagesAggregate + 1 tallyAggregate = 4 verify tx
```

如果单次 compressed proof 链上 verify gas 仍稳定在约 `20.34M`，上面例子会减少 5 次链上 verifier 调用，链上 gas 节省会明显高于本轮 five-signup。

## 11. 当前边界

当前 aggregate E2E 已经验证链上闭环，但还有几个边界：

- `processMessagesAggregate` 本轮只有 1 个 child，主要验证了 aggregate 接口和链上路径；还没有展示多 processMessages child 的成本优势。
- `tallyAggregate` 已经是 2 个 child，验证了多 child 聚合的链路。
- aggregate proving 会增加 prover 侧压力，本次 tally aggregate max RSS 约 `24.18GB`，processMessages aggregate max RSS 约 `18.35GB`。
- aggregate proof raw size 仍为 `1,272,546` bytes，和普通 compressed proof 接近，因此链上单次 verify gas 也接近普通 compressed proof。

## 12. 下一步

建议下一步构造更大 round fixture，用来真正测出 aggregation 的规模化收益：

- `processMessages child_count >= 2`
- `tally child_count >= 3`
- 保持 `processDeactivate` / `addNewKey` 仍为单 proof

然后记录：

- child proof 总数；
- aggregate proof 数；
- aggregate proving time / max RSS；
- aggregate proof raw bytes；
- 链上 verify gas；
- 最终 round tally 是否仍为预期结果。

## 13. 15 Signup / 15 Message 扩展测试（2026-07-10）

第 12 节计划的更大规模测试已经完成。本轮仍使用单批容量为 5 的
`2-1-1-5` 配置，但把初始 signup 和 vote message 都增加到 15，用于观察
多个 `processMessages` 和多个 `tally` proof 聚合后的实际收益。

测试结果：

```text
initial signups: 15
final state leaves: 16
vote messages: 15
processMessages child proofs: 3
tally child proofs: 4

non-aggregate verifier tx: 9
aggregate verifier tx: 4

non-aggregate total cost: 1.866945880 DORA
aggregate total cost: 0.850075730 DORA
saved: 1.016870150 DORA
```

两条路径的 round 均完整结束，所有交易 `code = 0`。Aggregate 合约最终记录：

```json
{
  "completed": {
    "process_deactivate": 1,
    "add_new_key": 1,
    "process_messages": 3,
    "tally": 4
  },
  "next_stage": null,
  "is_complete": true,
  "verified_proofs": 4
}
```

## 14. 测试数据

### 14.1 Signup 和 StateLeaf

本轮先创建 15 个 signup，state index 为 `0..14`。随后执行一次
`processDeactivate`，停用 state 13 和 state 14 的旧 key；`addNewKey` 为 state
14 追加 replacement key，新 StateLeaf 位于 state 15。因此 tally 阶段处理的是
16 个 StateLeaf：

```text
initial signup count: 15
deactivated old states: 13, 14
replacement state: 15
final numSignUps: 16
```

对应 fixture 实现在
[`round_fixture.rs`](../crates/proof-core/src/round_fixture.rs#L356)，导出工具是
[`export_fifteen_signup_round.rs`](../crates/proof-core/src/bin/export_fifteen_signup_round.rs)。

### 14.2 Vote message

15 条 message 都是 vote command。具体安排如下：

| Message 来源 | Vote option | Weight | 预期结果 | 原因 |
| --- | ---: | ---: | --- | --- |
| old state 13 | 1 | 2 | invalid | key 已在 deactivate 阶段停用 |
| old state 14 | 2 | 3 | invalid | old key 已停用并完成 key replacement |
| state 0..11 | `stateIndex % 5` | `optionIndex + 1` | valid | 每个 state 提交一条正常 vote |
| replacement state 15 | 4 | 5 | valid | 使用 replacement key 投票 |
| state 12 | - | - | 无 message | 本轮不投票 |

有效 vote 共 13 条，两个旧 key 的 message 不会修改 state。预期原始 tally 是：

```text
option 0: 3
option 1: 6
option 2: 6
option 3: 8
option 4: 15

expected raw tally: [3, 6, 6, 8, 15]
```

### 14.3 Batch 划分

`processMessages` 每批处理 5 条 message，所以 15 条 message 产生 3 个 child
proof：

```text
fifteen-signup-process-messages-0
fifteen-signup-process-messages-1
fifteen-signup-process-messages-2
```

`tally` 每批处理 5 个 StateLeaf。最终有 16 个 StateLeaf，因此产生 4 个 child
proof，最后一批包含 1 个实际 StateLeaf和 4 个 padding leaf：

```text
fifteen-signup-tally-0  -> state 0..4
fifteen-signup-tally-1  -> state 5..9
fifteen-signup-tally-2  -> state 10..14
fifteen-signup-tally-3  -> state 15 + padding
```

## 15. 高性能机器 Proving 流程

高性能机器负责生成 9 个普通 compressed proof，然后生成两个 aggregate
proof。脚本入口是
[`run_fifteen_signup_sp1_aggregation.sh`](../scripts/run_fifteen_signup_sp1_aggregation.sh)。

执行命令：

```bash
mkdir -p logs metrics sp1-proofs

nohup env \
  SP1_TARGET_DIR=/tmp/zkvm-amaci-sp1-target \
  CARGO_TARGET_DIR=/tmp/zkvm-amaci-sp1-agg-target \
  scripts/run_fifteen_signup_sp1_aggregation.sh \
  > logs/fifteen-signup-aggregation-$(date +%Y%m%d-%H%M%S).out 2>&1 &
```

脚本按顺序执行以下工作：

1. 生成 `processDeactivate` 和 `addNewKey` compressed proof。
2. 生成 3 个 `processMessages` compressed child proof。
3. 生成 4 个 `tally` compressed child proof。
4. 聚合 3 个 `processMessages` child proof。
5. 聚合 4 个 `tally` child proof。
6. 生成 CosmWasm execute msg 并打包 artifacts。

所有 proving job 串行执行，没有同时启动多个 SP1 prover。

### 15.1 Aggregation 连续性检查

`processMessages` aggregation 检查：

```text
child[i].batchEndHash == child[i + 1].batchStartHash
child[i].newStateCommitment == child[i + 1].currentStateCommitment
```

它还要求所有 child 的 `packedVals`、coordinator key hash、deactivate commitment
和 poll id 相同。

`tally` aggregation 检查：

```text
batch number: 0 -> 1 -> 2 -> 3
child[i].newTallyCommitment == child[i + 1].currentTallyCommitment
```

所有 tally child 还必须使用同一个 state commitment。相关检查在
[`aggregate.rs`](../crates/proof-core/src/aggregate.rs) 中实现。

### 15.2 Artifacts

高性能机器生成的压缩包：

```text
sp1-proofs/fifteen-signup-aggregate-artifacts.tar.gz
```

本地文件大小约 `11 MB`，SHA-256：

```text
62caf1b33d8357106d16dbc5fa37c3cd938f7e86f098deffc3d2be95c527345b
```

两个 aggregate proof 的链上输入：

| Artifact | Bytes |
| --- | ---: |
| `fifteen-signup-process-messages.aggregate.sp1-compressed-proof.bytes` | 1,272,546 |
| `fifteen-signup-process-messages.aggregate.public.bin` | 301 |
| `fifteen-signup-process-messages.aggregate.vkey.bin` | 32 |
| `fifteen-signup-tally.aggregate.sp1-compressed-proof.bytes` | 1,272,546 |
| `fifteen-signup-tally.aggregate.public.bin` | 149 |
| `fifteen-signup-tally.aggregate.vkey.bin` | 32 |

压缩包还包含 9 个 non-aggregate execute msg 和两个 aggregate execute msg，
因此同一批 proof 可以跑 aggregate 与 non-aggregate 两条链上路径。

这次下载的压缩包没有包含高性能机器上的 `logs/` 和 `metrics/`，因此本节只记录
可复核的 artifact 大小，没有填写 15-signup aggregation 的 proving 时间和峰值
内存。后续需要比较树形聚合时，应把对应 metrics 文件一并带回。

## 16. 本地准备与执行

压缩包从高性能机器下载后放入 `zkvm-amaci`，从仓库根目录解压：

```bash
tar -xzf fifteen-signup-aggregate-artifacts.tar.gz
```

解压后，两份 aggregate execute msg 与 raw proof/public/vkey 重新生成的内容一致：

```text
process_messages_aggregate_msg=ok
tally_aggregate_msg=ok
```

本轮使用的 manifest：

| 路径 | Manifest |
| --- | --- |
| Aggregate | [`round-e2e.fifteen-signup.aggregate.example.json`](../fixtures/round-e2e.fifteen-signup.aggregate.example.json) |
| Non-aggregate | [`round-e2e.fifteen-signup.example.json`](../fixtures/round-e2e.fifteen-signup.example.json) |

Aggregate E2E：

```bash
node scripts/run_cosmwasm_round_e2e.mjs \
  --manifest fixtures/round-e2e.fifteen-signup.aggregate.example.json
```

Non-aggregate E2E：

```bash
node scripts/run_cosmwasm_round_e2e.mjs \
  --manifest fixtures/round-e2e.fifteen-signup.example.json
```

本地链参数：

```text
RPC: http://127.0.0.1:26657
chain ID: zkvm-amaci-devnet
denom: peaka
signer: dora1y3uljxavztyw7tvlj3agacaja9scj5x0pkk5ml
cost gas price: 10000000000 peaka/gas
```

本地 devnet 的 `signGasPricePeaka` 是 0，所以交易实际 fee 显示为 0。下文 DORA
金额按 `10000000000 peaka/gas` 计算，用于估算相同 gas 在目标费率下的成本。

## 17. 15-Signup Aggregate 链上结果

结果文件：

```text
round-e2e-results/20260710053854/summary.json
round-e2e-results/20260710053854/summary.md
```

部署结果：

```text
code ID: 8
contract: dora1vguuxez2h5ekltfj9gjd62fs5k4rl2zy5hfrncasykzw08rezpfs7p9cxm
round ID: fifteen-signup-15-message-2-1-1-5-aggregate
```

交易明细：

| 步骤 | 高度 | Gas wanted | Gas used | 估算 DORA | 交易哈希 |
| --- | ---: | ---: | ---: | ---: | --- |
| store_code | 68515 | 3,855,369 | 3,506,491 | 0.035064910 | `630940AEC9865F7FE41F0CBAC47F723898B439AE40D01B836684ED9D184D6C0B` |
| instantiate_round | 68516 | 200,045 | 144,493 | 0.001444930 | `86B948509BE613DDD8990FFA522E199DCF62D7C16ED10A753FCBE44BD7CEEE83` |
| process_deactivate | 68517 | 300,000,000 | 20,339,517 | 0.203395170 | `2AEE53061BE3A179700C1FFD16B5BF174156C32DD2E24AB286DBDDE61E213053` |
| add_new_key | 68518 | 300,000,000 | 20,339,831 | 0.203398310 | `7953E7C32EDDCB4525C3059D2E65A7A1C6E2226D7E5F9AC57FAB87D997E54FD0` |
| process_messages_aggregate | 68519 | 300,000,000 | 20,339,777 | 0.203397770 | `721A2EA139207E67340D3C2EBABF862AB9D91D2B1CF816FD14F1ED5DDBB49126` |
| tally_aggregate | 68520 | 300,000,000 | 20,337,464 | 0.203374640 | `0BD38B0D3CC4AC59B723AD6066E7730ED5FCAAA09B3E9624D79651D36377EC16` |

只计算 4 个 proof verify：

```text
gas: 81,356,589
estimated cost: 0.813565890 DORA
```

包含 store code 和 instantiate：

```text
total gas: 85,007,573
estimated total cost: 0.850075730 DORA
```

合约最终状态：

```json
{
  "round_id": "fifteen-signup-15-message-2-1-1-5-aggregate",
  "expected": {
    "process_deactivate": 1,
    "add_new_key": 1,
    "process_messages": 3,
    "tally": 4
  },
  "completed": {
    "process_deactivate": 1,
    "add_new_key": 1,
    "process_messages": 3,
    "tally": 4
  },
  "next_stage": null,
  "is_complete": true,
  "verified_proofs": 4
}
```

## 18. 15-Signup Non-Aggregate 基准

结果文件：

```text
round-e2e-results/20260710054137/summary.json
round-e2e-results/20260710054137/summary.md
```

部署结果：

```text
code ID: 10
contract: dora13we0myxwzlpx8l5ark8elw5gj5d59dl6cjkzmt80c5q5cv5rt54qlfsrhc
round ID: fifteen-signup-15-message-2-1-1-5
```

交易明细：

| 步骤 | 高度 | Gas wanted | Gas used | 估算 DORA | 交易哈希 |
| --- | ---: | ---: | ---: | ---: | --- |
| store_code | 68547 | 3,855,369 | 3,506,491 | 0.035064910 | `9402543EBD11CFEAF4EA59563FBCD473C46FDDE485114D63F87618361D51C8F7` |
| instantiate_round | 68548 | 198,487 | 143,380 | 0.001433800 | `E944258153C3D35E99ABD0767309CC58456FE9889D3E5D18CB4014AA7C3C6A1E` |
| process_deactivate | 68549 | 300,000,000 | 20,339,171 | 0.203391710 | `8EB10C5961C435F974F81D2C66B50B80A45D1AEFFA82B00897621C75627CB2EB` |
| add_new_key | 68550 | 300,000,000 | 20,339,486 | 0.203394860 | `634B77536C0721FEE470DA19A3723EEAF7F0F6F5C089D02699D8B0C642D6188E` |
| process_messages_0 | 68551 | 300,000,000 | 20,339,151 | 0.203391510 | `2DF556D0027C7AE5898AE5D58D4EFAF58A97AF15A5FB183F27D7D4EAD3C98D6F` |
| process_messages_1 | 68552 | 300,000,000 | 20,339,115 | 0.203391150 | `8EC92DA780D9CC1192692EE8EF55E8D7A8C879161D095341BCDFE99A091DB0FB` |
| process_messages_2 | 68553 | 300,000,000 | 20,339,147 | 0.203391470 | `4767DB15103033E798831049C5A1B9A7981205CCBF19C23FCDD53A7B87B91EB0` |
| tally_0 | 68554 | 300,000,000 | 20,337,176 | 0.203371760 | `4392184E55583C1BD288DEA482DF0A4E609C2800031897F8154ECCC25A565ADF` |
| tally_1 | 68555 | 300,000,000 | 20,337,134 | 0.203371340 | `92BB8E7EF52189FF90F3D9727B92BA5B152FACE0D0BED7858410BC1E0E983037` |
| tally_2 | 68556 | 300,000,000 | 20,337,172 | 0.203371720 | `D7A2B721366C01AC7B523900B5ABC9EEEFC8C5CDB2AC7751C7A233F40BC2D934` |
| tally_3 | 68557 | 300,000,000 | 20,337,165 | 0.203371650 | `5B76B1C8D7E1648204468169C838EF61039EAFE65C616FA85C61BCBB1A20790B` |

只计算 9 个 proof verify：

```text
gas: 183,044,717
estimated cost: 1.830447170 DORA
```

包含 store code 和 instantiate：

```text
total gas: 186,694,588
estimated total cost: 1.866945880 DORA
```

最终状态中的 `completed` 与 aggregate 路径相同，区别是
`verified_proofs = 9`。

## 19. 15-Signup Aggregate vs Non-Aggregate

| 指标 | Non-aggregate | Aggregate | 节省 |
| --- | ---: | ---: | ---: |
| 链上 proof verify 交易数 | 9 | 4 | 5 |
| `processMessages` verifier 调用 | 3 | 1 | 2 |
| `tally` verifier 调用 | 4 | 1 | 3 |
| proof verify gas | 183,044,717 | 81,356,589 | 101,688,128 |
| proof verify 估算 DORA | 1.830447170 | 0.813565890 | 1.016881280 |
| proof verify gas 降幅 | - | - | 55.554% |
| 总 gas | 186,694,588 | 85,007,573 | 101,687,015 |
| 总估算 DORA | 1.866945880 | 0.850075730 | 1.016870150 |
| 总成本降幅 | - | - | 54.467% |

单次 compressed proof 和单次 aggregate compressed proof 的链上 gas 都在约
`20.34M`。本轮节省来自 verifier 调用次数从 9 次降到 4 次，而不是单次
aggregate proof 验证变便宜。

`processDeactivate` 和 `addNewKey` 各自只有一个 proof，没有参与聚合。实际减少的
5 次调用来自：

```text
3 processMessages -> 1 processMessagesAggregate  (减少 2 次)
4 tally           -> 1 tallyAggregate            (减少 3 次)
```

## 20. Tally 正确性

Rust 测试
[`fifteen_signup_round_fixture_executes_and_links_aggregated_batches`](../crates/proof-core/tests/core_smoke.rs#L322)
执行全部 9 个 stage input，并检查：

- 15 条 message 中有 13 条有效、2 条无效；
- 三个 `processMessages` batch 的 message hash 与 state commitment 连续；
- 四个 `tally` batch 的 batch number 与 tally commitment 连续；
- 最后一个 `processMessages` state commitment 等于第一个 `tally` state commitment；
- 汇总后的原始结果等于 `[3, 6, 6, 8, 15]`；
- aggregate public output 的 child count 分别是 3 和 4。

链上合约不会直接显示原始 tally 数组。它验证 SP1 proof，并依据已验证的 aggregate
public output 推进 round。原始 tally 的正确性由 Rust guest 执行、child proof、
aggregate proof 和链上 verifier 串起来保证；合约最终的 `is_complete = true` 表明
两组 aggregate proof 都已验证并完成对应阶段。

## 21. 本轮结论和后续边界

15-signup 测试补上了 five-signup 测试缺少的多 child 场景。三个
`processMessages` child 和四个 `tally` child 都已完成聚合，链上总成本下降
`54.467%`。

当前实现仍是扁平聚合：一个 aggregation job 同时加载同一阶段的全部 child
proof。child 数继续增加时，aggregate proving 的内存和时间也会增长。大规模
round 应改用固定 fan-in 的树形聚合，例如每 4 或 5 个 proof 聚合一组，再聚合
上一层输出。最终链上仍只验证一个 stage aggregate proof，但单个 prover job 的
输入规模可以保持稳定。

## 22. 50-Signup 树形聚合 E2E

在 15-signup 扁平聚合完成后，本项目进一步实现了固定 `fan-in = 5` 的树形聚合，
并使用 50 个 signup、50 条 message 的确定性 fixture 完成了一轮本地链 E2E。

测试场景：

```text
state tree depth: 3
batch size: 5
initial signups: 50
final state leaves after AddNewKey: 51
messages: 50
processMessages base proofs: 10
tally base proofs: 11
all base proofs: 23
recursive aggregation nodes: 8
final on-chain proofs: 1
```

本轮最终状态：

```text
round complete: true
verified proofs: 1
completed.process_deactivate: 1
completed.add_new_key: 1
completed.process_messages: 10
completed.tally: 11
```

这里的 `verified_proofs = 1` 表示 CosmWasm 合约只调用了一次 SP1 compressed
verifier。最终 Round Root proof 已递归验证全部 23 个基础 proof，并在 public
values 中携带各阶段数量、身份信息、状态连续性和最终 commitment。

## 23. 固定 Fan-In 树结构

树形聚合使用每个节点最多 5 个 child proof 的结构。processMessages 的 10 个
leaf proof 聚合为：

```text
10 leaves -> 2 level-1 nodes -> 1 processMessages root
level widths: [2, 1]
recursive nodes: 3
```

tally 的 11 个 leaf proof 聚合为：

```text
11 leaves -> 3 level-1 nodes -> 1 tally root
level widths: [3, 1]
recursive nodes: 4
```

最终 Round Root 节点递归验证四个直接 child：

```text
processDeactivate base proof
addNewKey base proof
processMessages tree root
tally tree root
                 -> final Round Root proof
```

因此递归节点总数为：

```text
3 processMessages nodes + 4 tally nodes + 1 Round Root node = 8
```

树形聚合入口和约束分别位于：

| 模块 | 文件 | 作用 |
| --- | --- | --- |
| 树形聚合公共类型与检查 | [`tree_aggregate.rs`](../crates/proof-core/src/tree_aggregate.rs) | 校验节点类型、层级、child 数、阶段连续性和 Round Root public output。 |
| SP1 tree guest | [`proof-sp1-tree-program/src/main.rs`](../crates/proof-sp1-tree-program/src/main.rs) | 在 zkVM 内递归验证 child proof 并提交树节点 public values。 |
| SP1 tree host | [`proof-sp1-tree-host/src/main.rs`](../crates/proof-sp1-tree-host/src/main.rs) | 构建单个树节点、生成 compressed proof 和最终 Round Root artifacts。 |
| 树形调度脚本 | [`run_sp1_tree_round.sh`](../scripts/run_sp1_tree_round.sh) | 按 fan-in 5 流式构建 processMessages、tally 和 Round Root。 |
| 50-signup 完整流程 | [`run_fifty_signup_sp1_tree_e2e.sh`](../scripts/run_fifty_signup_sp1_tree_e2e.sh) | 生成基础 proofs、构建聚合树、验证并打包 artifacts。 |
| CosmWasm verifier | [`contract.rs`](../crates/cosmwasm-amaci-round/src/contract.rs) | 使用固定 tree vkey 验证最终 Round Root，并一次性完成所有 round stage。 |
| 本地链 E2E manifest | [`round-e2e.fifty-signup.tree.example.json`](../fixtures/round-e2e.fifty-signup.tree.example.json) | 定义本轮规模、预期 stage 数、vkey 配置和最终 proof 消息。 |

## 24. 高性能机器产物

高性能机器完成全部基础 proof 和树形递归 proof 后，输出：

```text
tree round build ok
tree round proof verify ok
tree round suite ok
fifty signup SP1 tree E2E artifacts ready
```

最终归档：

```text
sp1-proofs/fifty-signup-tree-round-artifacts.tar.gz
```

归档 SHA-256：

```text
688a2903d922c07c9429a9d71d1684f6e49861f6480d8cadc597eb8bc34b4415
```

归档中的关键文件：

| 文件 | 大小/作用 |
| --- | --- |
| `round-root.proof.bytes` | 1,272,546 bytes，最终 SP1 compressed proof。 |
| `round-root.public.bin` | 513 bytes，Round Root public values。 |
| `round-root.vkey.bin` | 32 bytes，tree program compressed vkey hash。 |
| `round-root.verify-compressed.msg.json` | 1,697,476 bytes，可直接提交 CosmWasm 的 Base64 JSON 消息。 |
| `contract-config.json` | 固定 base/tree vkey、poll ID 和 coordinator public key hash。 |
| `manifest.json` | leaf 数量、树宽度、递归节点数量和 root 路径。 |

树形 proving 指标：

```text
direct_child_count: 4
leaf_count: 23
final Round Root node proving elapsed: 84,379 ms
proof_bytes: 1,272,546
public_bytes: 513
```

这里的 `84,379 ms` 只统计最终 Round Root 节点，不是全部 8 个递归节点的累计
proving 时间。完整树的 wall time 和峰值内存由高性能机器上的 tree suite
`time_log` 记录；后续优化比较应同时采集每个节点和整棵树两个口径。

## 25. 本地 CosmWasm E2E

本地测试使用：

```text
chain: zkvm-amaci-devnet
RPC: http://127.0.0.1:26657
cost gas price: 10000000000 peaka/gas
code ID: 11
contract: dora1x8gwn06l85q0lyncy7zsde8zzdn588k2dck00a8j6lkprydcutwqtlh33s
```

执行命令：

```bash
npm run build:round-contract

node scripts/run_cosmwasm_round_e2e.mjs \
  --manifest fixtures/round-e2e.fifty-signup.tree.example.json
```

结果保存在：

```text
round-e2e-results/20260711041227/summary.json
round-e2e-results/20260711041227/summary.md
```

## 26. 50-Signup 链上 Gas 和 DORA

| 步骤 | 高度 | Gas wanted | Gas used | 估算 DORA | 交易哈希 |
| --- | ---: | ---: | ---: | ---: | --- |
| store_code | 84632 | 3,937,729 | 3,581,364 | 0.035813640 | `1F332818F6B86B2B5D283A05B365DCEA78287E1B9CD211F1996E3E65659E3EF0` |
| instantiate_round | 84633 | 235,868 | 170,081 | 0.001700810 | `D0F0CD4C5789543CDDA1495A7C332540B548E383F1781F333943D6E72B648B27` |
| round_root | 84634 | 300,000,000 | 20,354,283 | 0.203542830 | `1F13B7C8E7C1BA11F69869A4464D67897797422F08B974A7117D377FB8A94557` |

汇总：

```text
total gas used: 24,105,728
total estimated cost: 0.241057280 DORA
round-root verify gas: 20,354,283
round-root verify estimated cost: 0.203542830 DORA
```

本地 devnet 的 `signGasPricePeaka = 0`，因此浏览器显示的实际交易 fee 为
`0 DORA`。表中的 DORA 使用 `10000000000 peaka/gas` 作为成本参数计算，便于和
之前的 E2E 保持一致。

## 27. Tally 正确性和验证边界

50 条确定性 message 的预期原始 tally 为：

```text
[10, 20, 27, 36, 50]
```

高性能机器上的 fixture 执行和基础 proof 生成检查每个 processMessages/tally
batch 的前后 commitment；树形聚合继续约束所有相邻 child 的顺序、数量和
commitment 连续性。最终 Round Root public values 包含经过验证的
`final_tally_commitment`，CosmWasm 合约验证该 Round Root proof 和固定 vkey。

需要明确的是，合约不会把明文数组 `[10, 20, 27, 36, 50]` 作为状态保存或直接
逐项比较。链上验证的是与该结果绑定的最终 tally commitment。E2E runner 中的
`expectedRawResults` 用于报告和 fixture 对照；明文 tally 与 commitment 的对应
关系由 Rust guest 执行和 SP1 proof 保证。

## 28. 50-Signup Aggregation Gas 对比

本次没有在链上重新提交 50-signup 的全部 23 个 non-aggregate proof，因此下面的
树形聚合数据是本轮实测值，non-aggregate 数据是基于第 18 节 15-signup
non-aggregate 实测结果得到的估算值，不能混淆为同轮实测。

已有 non-aggregate 实测基准：

```text
processDeactivate:          20,339,171 gas
addNewKey:                  20,339,486 gas
processMessages average:    20,339,137.67 gas
tally average:              20,337,161.75 gas
```

50-signup non-aggregate 路径需要：

```text
1 processDeactivate + 1 addNewKey + 10 processMessages + 11 tally
= 23 verifier calls
```

估算公式：

```text
20,339,171
+ 20,339,486
+ 10 * 20,339,137.67
+ 11 * 20,337,161.75
= 467,778,813 gas
```

本轮树形聚合 Round Root 的实测 verifier Gas 为：

```text
20,354,283 gas
```

对比结果：

| 指标 | Non-aggregate 估算 | Tree aggregation 实测 | 节省 |
| --- | ---: | ---: | ---: |
| 链上 proof verify 交易数 | 23 | 1 | 22 |
| proof verify gas | 467,778,813 | 20,354,283 | 447,424,530 |
| proof verify 估算 DORA | 4.677788130 | 0.203542830 | 4.474245300 |
| proof verify gas 降幅 | - | - | 95.649% |
| 包含 store/instantiate 的总 gas | 471,530,258 | 24,105,728 | 447,424,530 |
| 包含 store/instantiate 的总估算 DORA | 4.715302580 | 0.241057280 | 4.474245300 |
| 总 Gas 降幅 | - | - | 94.888% |

两条路径使用相同的本轮 `store_code = 3,581,364 gas` 和
`instantiate_round = 170,081 gas` 计算总成本，因此总成本差额全部来自减少的
22 次 verifier 调用。DORA 仍按 `10000000000 peaka/gas` 估算。

这项节省只描述链上验证成本。树形聚合需要额外生成 8 个递归 proof，增加了链下
prover 的时间、内存和计算成本；它没有让单个 compressed proof 的链上验证更便宜，
而是把 23 次约 `20.34M gas` 的验证收敛成 1 次约 `20.35M gas` 的验证。

## 29. 50-Signup 树形聚合结论

本轮证明了固定 fan-in 树形聚合可以把 23 个基础 proof 收敛为一个约 1.27 MB 的
最终 compressed proof，并在链上通过一次约 `20.35M gas` 的 verifier 调用完成
整个 round。随着 signup/message 数增加，最终链上 proof 数和单次验证成本不会
随 leaf proof 数线性增加；增加的成本主要转移到链下递归 proving 节点。

与 non-aggregate 基准估算相比，本轮减少 22 次 verifier 调用，预计节省
`447,424,530 gas`，对应 `4.474245300 DORA`，proof verify Gas 降幅约
`95.649%`。要获得完全同条件的实测差值，仍应使用同一份 50-signup fixture、同一
合约 Wasm 和同一 devnet 配置运行 non-aggregate manifest，再以两份
`summary.json` 进行对比。

## 30. 生产生命周期修正：Online Proof + Finalization Root

第 22-29 节记录的是已经完成的 `AMACITR2` 全 Round Root 实测。该模型把
ProcessDeactivate、AddNewKey、ProcessMessages 和 Tally 全部延迟到一个最终 proof
确认。后续业务模型确认 ProcessDeactivate/AddNewKey 在 round 进行期间需要及时
生效，因此生产实现已调整为：

```text
Round open:
  ProcessDeactivate proof -> 单独验证并更新 deactivate state
  AddNewKey proof          -> 单独验证并消费 nullifier

Close round:
  冻结 state/message/deactivate checkpoint

Post-round:
  ProcessMessages Tree Root
  Tally Tree Root
          -> Finalization Root
```

新的 tree public codec 为 `AMACITR3`，Finalization Root 只有两个直接 child，不再
递归验证已经在链上确认过的两个在线 proof。旧 `AMACITR2` proof 与新 tree program
vkey 不兼容，需要在高性能机器重新生成。

50-signup 新流程的链上 proof verifier 调用为：

```text
1 ProcessDeactivate
1 AddNewKey
1 Finalization Root
= 3 verifier calls
```

相对于 23 个 base proof 全部分别验证，新的生产模型减少 20 次 verifier 调用。使用
第 18 节的单次在线 proof 实测 Gas 和第 26 节旧 Round Root 的单次 tree verifier
Gas 作为近似值：

| 指标 | Non-aggregate 估算 | Online + Finalization 估算 | 节省 |
| --- | ---: | ---: | ---: |
| proof verifier 调用 | 23 | 3 | 20 |
| proof verify gas | 467,778,813 | 61,032,940 | 406,745,873 |
| proof verify 估算 DORA | 4.677788130 | 0.610329400 | 4.067458730 |
| proof verify Gas 降幅 | - | - | 86.953% |

这里还没有计入 `close_round` 的普通合约交易 Gas。它不执行 proof verifier，预计远
低于一次约 `20.34M gas` 的 compressed proof 验证。最终准确数据必须等新的
Finalization Root artifacts 生成后，在同一 devnet 完成 E2E 再写入。

新实现入口：

- [`sp1_tree_aggregation.md`](sp1_tree_aggregation.md)：在线和结算生命周期设计；
- [`contract.rs`](../crates/cosmwasm-amaci-round/src/contract.rs)：在线 proof、checkpoint
  和 Finalization Root 状态机；
- [`tree_aggregate.rs`](../crates/proof-core/src/tree_aggregate.rs)：`AMACITR3`
  Finalization Root 约束；
- [`run_sp1_tree_finalization.sh`](../scripts/run_sp1_tree_finalization.sh)：高性能机器
  finalization tree runner。
