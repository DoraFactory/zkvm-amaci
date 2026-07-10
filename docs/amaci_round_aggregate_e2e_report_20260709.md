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
