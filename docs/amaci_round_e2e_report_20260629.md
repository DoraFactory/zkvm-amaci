# AMACI zkVM Five-Signup Round E2E 报告

## 1. 测试结论

本次 E2E 在本地 `dorad` CosmWasm devnet 上，验证了一轮真实的 `2-1-1-5` AMACI round。证明系统使用 SP1 compressed STARK proof，链上合约逐个验证 5 个 proof。

最终结果：

```text
round complete: true
verified proofs: 5
total estimated cost: 10.530875500 DORA
contract: dora1eyfccmjm6732k7wp4p6gdjwhxjwsvje44j0hfx8nkgrm8fs7vqfs5u9wsh
code id: 5
```

完整机器可读结果在：

```text
round-e2e-results/20260629034945/summary.json
```

## 2. Round 数据

本次 fixture 名称：

```text
five-signup-2-1-1-5
```

基础规模：

```text
state tree depth: 2
vote option tree depth: 1
process message batch size: 5
tally batch size: 5
初始 signup 数量: 5
addNewKey 后最终 state leaf 数量: 6
```

业务数据：

| 项目 | 值 |
| --- | --- |
| 初始 signup state index | `0, 1, 2, 3, 4` |
| deactivate state index | `3, 4` |
| addNewKey | 旧 `stateIndex=4` -> 新 `stateIndex=5` |
| vote message 数量 | 5 |
| 预期 raw result | `[1, 0, 0, 0, 10]` |

5 条 vote message：

| 顺序 | 投票人 / key | stateIndex | vote option | weight | 预期结果 |
| ---: | --- | ---: | ---: | ---: | --- |
| 1 | old user 3 | 3 | 1 | 1 | 无效，old key 已 deactivate |
| 2 | old user 4 | 4 | 2 | 2 | 无效，old key 已 deactivate 且已换 key |
| 3 | user 0 | 0 | 0 | 1 | 有效 |
| 4 | new user 5 | 5 | 4 | 5 | 有效，addNewKey 后的新 key |
| 5 | user 0 | 0 | 4 | 5 | 有效 |

有效票贡献：

```text
option0 += 1
option4 += 5
option4 += 5
```

最终预期 raw result：

```text
[1, 0, 0, 0, 10]
```

## 3. Round 流程

本轮业务流程：

```text
signup 0..4
-> deactivate 3,4
-> processDeactivate proof
-> addNewKey: old stateIndex 4 -> new stateIndex 5
-> 5 条 vote message
-> processMessagesFull proof
-> tally0 proof
-> tally1 proof
```

在 `2-1-1-5` 规模下，本轮一共需要 5 个 proof：

| 顺序 | Stage | 说明 |
| ---: | --- | --- |
| 1 | `processDeactivate` | 处理 `stateIndex=3,4` 的 deactivate message。 |
| 2 | `addNewKey` | 证明旧 `stateIndex=4` 已 deactivate，并授权新 key / 新 `stateIndex=5`。 |
| 3 | `processMessagesFull` | 一次处理全部 5 条 vote message。 |
| 4 | `tally0` | tally `stateIndex=0..4`。 |
| 5 | `tally1` | tally `stateIndex=5..9`，其中只有 `stateIndex=5` 是非空新增 leaf。 |

为什么 tally 是两次：`addNewKey` 后最终 state leaf 数量是 6，而单个 `2-1-1-5` tally batch 只能处理 5 个 leaf，所以需要 `ceil(6 / 5) = 2` 个 tally proof。

## 4. Proof 输入与产物

真实 proof 输入和预期 public output 文件在：

```text
fixtures/five-signup-round/manifest.json
fixtures/five-signup-round/round.json
fixtures/five-signup-round/five-signup-process-deactivate.input.json
fixtures/five-signup-round/five-signup-add-new-key.input.json
fixtures/five-signup-round/five-signup-process-messages-full.input.json
fixtures/five-signup-round/five-signup-tally-0.input.json
fixtures/five-signup-round/five-signup-tally-1.input.json
```

本次链上 E2E 使用的 SP1 compressed proof execute message：

```text
sp1-proofs/five-signup-process-deactivate.verify-compressed.msg.json
sp1-proofs/five-signup-add-new-key.verify-compressed.msg.json
sp1-proofs/five-signup-process-messages-full.verify-compressed.msg.json
sp1-proofs/five-signup-tally-0.verify-compressed.msg.json
sp1-proofs/five-signup-tally-1.verify-compressed.msg.json
```

这些 `verify-compressed.msg.json` 文件是直接提交给 CosmWasm 合约的 execute msg，内部包含：

```text
compressed STARK proof bytes
public values bytes
SP1 vkey hash
```

## 5. CosmWasm 合约实现

E2E 合约位置：

```text
crates/cosmwasm-amaci-round
```

关键文件：

```text
crates/cosmwasm-amaci-round/src/contract.rs
crates/cosmwasm-amaci-round/src/msg.rs
crates/cosmwasm-amaci-round/src/state.rs
```

这个合约是 round 级别的 proof 验证和成本统计 harness，不是最终生产版 AMACI 业务合约。

关键逻辑：

1. `instantiate` 存储本轮预期计划：

```json
{
  "process_deactivate": 1,
  "add_new_key": 1,
  "process_messages": 1,
  "tally": 2
}
```

2. `execute` 接收 `VerifyCompressedStage` 消息，字段包括：

```text
stage
proof
public_values
vkey_hash
```

3. 每次验证 proof 前，合约先检查当前应该执行的 stage。强制顺序是：

```text
processDeactivate -> addNewKey -> processMessages -> tally -> tally
```

4. SP1 compressed proof 验证调用：

```rust
SP1CompressedVerifierRaw::verify_with_public_values(proof, public_values, vkey_hash)
```

5. proof 验证通过后，合约更新：

```text
completed.<stage> += 1
verified_proofs += 1
```

6. `query RoundState` 返回：

```text
round_id
expected
completed
next_stage
is_complete
verified_proofs
```

当前 E2E 合约暂未实现的生产业务约束：

- 没有 round 时间窗口。
- 没有 admin/operator 权限控制。
- 没有 signup/vote period 检查。
- 没有用户押金、注册、投票入口等完整业务状态机。
- 合约验证 proof 有效性和 stage 顺序；AMACI 业务语义由 zkVM proof 内部的 Rust 逻辑保证。

## 6. 链上执行结果

最终 round state：

```json
{
  "round_id": "five-signup-2-1-1-5",
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
  "verified_proofs": 5
}
```

交易发送账户：

```text
dora1y3uljxavztyw7tvlj3agacaja9scj5x0pkk5ml
```

合约地址：

```text
dora1eyfccmjm6732k7wp4p6gdjwhxjwsvje44j0hfx8nkgrm8fs7vqfs5u9wsh
```

## 7. Gas 与 DORA 成本

| 步骤 | 高度 | Gas wanted | Gas used | 估算 DORA | 交易哈希 |
| --- | ---: | ---: | ---: | ---: | --- |
| store code | 9547 | 3,822,887 | 3,476,962 | 0.347696200 | `30411FCB2CABE2137CE6E22F6A42C6E0EA800CC23CE173A20FE9FD28B54E6562` |
| instantiate round | 9548 | 196,783 | 142,162 | 0.014216200 | `8591555AEB5CFFC5020508EB1EBB694A8AF7CDC7C463CB9B5CBAAEAF55B07355` |
| processDeactivate | 9549 | 300,000,000 | 20,338,711 | 2.033871100 | `22C95D28A6355E2CBD6DE1009FCCF5A5BBC21CDF52D8F1AA5D7D3DB91C39224B` |
| addNewKey | 9550 | 300,000,000 | 20,339,002 | 2.033900200 | `81CAA795254E08B1CD049B10125214B533AC299A2E7FAA78FFC8558DB689A9D8` |
| processMessagesFull | 9551 | 300,000,000 | 20,338,657 | 2.033865700 | `EB7062E778B32624FAE85045077BAC4AC08EFE72A3580CE8313773F68E5F3FE3` |
| tally0 | 9552 | 300,000,000 | 20,336,634 | 2.033663400 | `A08D6BB451894C1EE4602EDCDD5EFA9C510ED56993987070E0B3A35D1585A79B` |
| tally1 | 9553 | 300,000,000 | 20,336,627 | 2.033662700 | `3CF06B3F2AB90019FA6ED0E357A32F4DE13CC0766F4BE633E03D2992AF4FA77D` |

总估算成本：

```text
10.530875500 DORA
```

只计算 5 个 proof verify，不包含 store code 和 instantiate：

```text
10.168962100 DORA
```

平均单个 compressed proof verify 成本：

```text
2.033792420 DORA
```

## 8. 本次使用的验证命令

构建 round 合约：

```bash
npm run build:round-contract
```

执行真实 five-signup E2E：

```bash
node scripts/run_cosmwasm_round_e2e.mjs \
  --manifest fixtures/round-e2e.five-signup.example.json
```

成功标准：

```text
roundState.is_complete == true
roundState.verified_proofs == 5
all transaction code values are 0
completed.process_deactivate == 1
completed.add_new_key == 1
completed.process_messages == 1
completed.tally == 2
fixture final raw tally result == [1, 0, 0, 0, 10]
```
