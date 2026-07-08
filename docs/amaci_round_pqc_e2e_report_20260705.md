# AMACI zkVM PQC Five-Signup Round E2E 报告

## 1. 测试结论

本次 E2E 在本地 `dorad` CosmWasm devnet 上，验证了一轮真实的 `2-1-1-5` AMACI round。证明系统使用 SP1 compressed STARK proof，AMACI zkVM 电路逻辑已切换到 PQC 版本：

```text
签名层: ML-DSA-65
KEM / 共享密钥层: ML-KEM-768
hash / Merkle / command / tally / deactivate / addNewKey: zkVM-friendly Rust 实现
```

链上合约逐个验证 5 个 SP1 compressed proof，并按 round 顺序推进状态。

最终结果：

```text
round complete: true
verified proofs: 5
total estimated cost: 1.053088310 DORA
contract: dora1pvrwmjuusn9wh34j7y520g8gumuy9xtl3gvprlljfdpwju3x7ucsp60ag2
code id: 6
```

完整机器可读结果在：

```text
round-e2e-results/20260705102941/summary.json
round-e2e-results/20260705102941/summary.md
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

## 4. PQC 实现说明

本轮 E2E 使用的是 `pqc-migration` 分支当前 PQC 实现。

本轮使用的 PQC Rust 库：

| 用途 | Rust crate | 当前版本 | 上游链接 | 标准背景 |
| --- | --- | --- | --- | --- |
| 用户命令授权签名 | `ml-dsa` | `0.1.1` | [crates.io/ml-dsa](https://crates.io/crates/ml-dsa), [docs.rs/ml-dsa](https://docs.rs/ml-dsa/latest/ml_dsa/), [RustCrypto/signatures](https://github.com/RustCrypto/signatures) | ML-DSA，NIST FIPS 204，原 CRYSTALS-Dilithium 标准化方向。 |
| 消息加密 KEM / 共享密钥封装 | `ml-kem` | `0.3.2` | [crates.io/ml-kem](https://crates.io/crates/ml-kem), [docs.rs/ml-kem](https://docs.rs/ml-kem/latest/ml_kem/), [RustCrypto/KEMs](https://github.com/RustCrypto/KEMs) | ML-KEM，NIST FIPS 203，原 CRYSTALS-Kyber 标准化方向。 |

关键替换：

| 层 | 当前实现 | 说明 |
| --- | --- | --- |
| 用户命令授权签名 | RustCrypto `ml-dsa` / ML-DSA-65 | 替换原先非 PQ 签名路径。 |
| 消息加密共享密钥 | RustCrypto `ml-kem` / ML-KEM-768 | 每条 message 独立 KEM ciphertext，保持原协议安全机制。 |
| deactivate/addNewKey shared key | ML-KEM-768 | `processDeactivate` 证明 deactivate ciphertext 与用户 KEM pubkey 绑定，`addNewKey` 再证明用户能打开。 |
| KEM witness 类型 | 定长 wrapper | `KemPublicKey = 1184 bytes`，`KemCiphertext = 1088 bytes`，codec 对空 slot 做零值压缩。 |

未做的协议层改动：

```text
没有改成 batch/session KEM
没有延迟 processDeactivate 的 KEM 正确性证明
没有改变 message/state/tally/deactivate commitment 链路
没有改变 processMessages/tally 的 batch 语义
```

也就是说，本轮只是将签名与密钥交换/封装迁移到 PQC primitive，未改变 AMACI round 的安全机制。

### 4.1 PQC 替换在协议中的关键作用

AMACI 协议里原本有两类会受量子攻击影响的公钥密码组件：

1. 用户对 command 的授权签名。
2. coordinator / user 之间用于消息加密、deactivate、addNewKey 的共享密钥建立。

本轮迁移分别用 ML-DSA 和 ML-KEM 替换这两类组件。

#### ML-DSA 的协议作用

ML-DSA 用于证明“这条 command 确实由当前 state leaf 绑定的用户授权”。

在 zkVM proof 内部，`processMessages` 和 `processDeactivate` 会执行：

```text
auth_pub_key_hash(public_key) == state_leaf.auth_pub_key_hash
verify_mldsa(public_key, signature, command_digest) == true
```

因此，攻击者即使能构造 message ciphertext，也不能伪造用户授权 command。PQC 迁移后，这一授权认证不再依赖 Ed25519 / ECDSA 这类椭圆曲线签名，而是依赖 ML-DSA-65。

它保护的是：

```text
vote command 授权
deactivate command 授权
state leaf 与用户认证 key 的绑定
```

#### ML-KEM 的协议作用

ML-KEM 用于建立每条消息和 deactivate leaf 里的 shared key。

在 `processMessages` 里，每条 vote message 保持独立 KEM ciphertext：

```text
kem_ciphertext --decapsulate(coord_priv_key)--> shared_key
shared_key --decrypt--> command
kem_ciphertext_compact(kem_ciphertext) == enc_pub_key commitment
```

这保证：

```text
每条 message 的加密 key 独立
message chain 仍绑定 enc_pub_key / ciphertext commitment
coordinator private key 是解密 command 的必要 witness
```

在 `processDeactivate` / `addNewKey` 里，ML-KEM 还用于证明 deactivate leaf 可被用户打开：

```text
processDeactivate:
  使用用户 KEM public key 生成 deactivate KEM ciphertext
  证明 ciphertext compact 字段进入 deactivate leaf
  证明 shared_key_hash 进入 deactivate leaf

addNewKey:
  使用旧用户 private key decapsulate deactivate KEM ciphertext
  重建 shared_key_hash
  证明 deactivate leaf 与旧用户 private key 绑定
```

这保留了原协议的关键安全机制：

```text
deactivate 阶段提交的 leaf 不是任意 hash
addNewKey 阶段必须证明旧用户能打开对应 deactivate ciphertext
旧 key -> 新 key 的迁移仍由 proof 内部约束串起来
```

### 4.2 相对未优化 / 未 PQC 版本的变化

本项目早期 Rust 版本的主要目标是“对标 Circom 电路语义”，因此保留了较多 SNARK/Circom 时代的实现特征。后续优化和 PQC 迁移分成两类：

```text
1. zkVM-friendly 实现优化
2. PQC primitive 替换
```

这两类改动的边界不同：zkVM-friendly 优化主要降低 guest 执行成本和证明资源；PQC 迁移主要替换协议里的公钥密码组件，使签名和密钥交换具备后量子安全属性。

#### 4.2.1 早期未优化版本的主要特征

早期实现为了贴近 Circom / zkSNARK 版本，保留了这些不适合 zkVM 的路径：

| 层 | 早期实现特征 | zkVM 里的问题 |
| --- | --- | --- |
| 曲线 / 签名 | BabyJubJub / EdDSA-Poseidon / arkworks 风格实现 | 大量 field arithmetic 和通用 Rust 抽象，zkVM 指令成本高。 |
| hash | Poseidon 风格接口 / field-oriented hashing | 适合 SNARK constraints，但不一定适合 RISC-V zkVM 执行。 |
| 数据结构 | `Vec<Field>`、动态 message/state/vote row、动态 Merkle sibling | guest 内反序列化、边界检查、动态分配更多。 |
| public output | field-oriented limbs | 与 zkVM byte public values / on-chain message 不够直接。 |
| codec | 动态长度字段较多 | 输入更大，decode 逻辑更重。 |
| proof 目标 | 先保证电路语义迁移正确 | 还没有针对 SP1/RISC0 proving 资源做 profile。 |

这些早期迁移初期用于确保 Rust 逻辑能和原 Circom 语义对齐；但在 zkVM 中，证明成本更多取决于实际 CPU 指令数、内存访问和 guest 代码路径，因此需要进一步改成 zkVM-friendly 结构。

#### 4.2.2 已完成的 zkVM-friendly 优化

在 PQC 迁移之前和迁移过程中，已经完成了以下实现层优化。下面每一项都给出对应源码位置，便于从报告直接跳到代码检查。

| 优化项 | 代码位置 | 具体做了什么 | 作用 |
| --- | --- | --- | --- |
| byte-oriented digest / public values | [`native_types.rs`](../crates/proof-core/src/native_types.rs#L7-L10), [`public_output.rs`](../crates/proof-core/src/public_output.rs#L5-L29), [`public_output.rs`](../crates/proof-core/src/public_output.rs#L41-L64) | 将 `Digest` / `Commitment` / `InputHash` / `Root` 定义为 `[u8; 32]`，public output 统一输出 byte digest。 | 更贴近 SP1/RISC0 public values / receipt journal，也更适合后续链上消息编码。 |
| SHA-256 native hash backend | [`hash_backend.rs`](../crates/proof-core/src/hash_backend.rs#L6-L19), [`hash_backend.rs`](../crates/proof-core/src/hash_backend.rs#L54-L82), [`hash_backend.rs`](../crates/proof-core/src/hash_backend.rs#L84-L96) | 将原本偏 Circom/Poseidon 的 field hash 路径替换为 domain-separated SHA-256 field/digest hash。 | 避免继续绑定 SNARK constraint-friendly hash，改成 zkVM/RustCrypto 更自然的 CPU 执行路径。 |
| NativeCommand 固定签名消息 | [`native_types.rs`](../crates/proof-core/src/native_types.rs#L12-L50), [`auth.rs`](../crates/proof-core/src/auth.rs#L42-L44), [`crypto.rs`](../crates/proof-core/src/crypto.rs#L41-L43) | 从 packed fields 解出固定 command 字段，再用 domain-separated SHA-256 生成 32-byte message digest。 | 签名校验输入固定、可复现，避免签名层继续依赖 Circom-style field serialization。 |
| Message / StateLeaf / VoteRow / Merkle sibling 固定化 | [`types.rs`](../crates/proof-core/src/types.rs#L91-L100), [`tally_votes.rs`](../crates/proof-core/src/circuits/tally_votes.rs#L22-L30) | `Message = [Field; 10]`，`StateLeaf = [Field; 10]`，`VoteRow = [Field; 5]`，`PathElement = [Field; 4]`，并在 tally 中限制当前 `2-1-1-5` 的 vote option row width。 | 减少 guest 中动态结构、serde、边界判断和堆分配。 |
| 固定长度 decrypt array | [`crypto.rs`](../crates/proof-core/src/crypto.rs#L77-L84), [`crypto.rs`](../crates/proof-core/src/crypto.rs#L113-L143), [`process_messages.rs`](../crates/proof-core/src/circuits/process_messages.rs#L185-L200) | `decrypt_without_check_array::<9>` 直接输出固定数组，`message_to_command` 不再拿动态 `Vec<Field>` 解 command。 | 降低 processMessages 热点路径里的分配和动态长度处理。 |
| byte-oriented Merkle path | [`merkle.rs`](../crates/proof-core/src/merkle.rs#L55-L90), [`merkle.rs`](../crates/proof-core/src/merkle.rs#L108-L153) | Merkle root/path 计算内部走 `Digest`，只在输入/输出边界做 field 与 digest 转换。 | 减少反复 field hash 包装，和 byte digest public output 保持一致。 |
| compact binary input/output codec | [`codec.rs`](../crates/proof-core/src/codec.rs#L15-L63), [`codec.rs`](../crates/proof-core/src/codec.rs#L65-L110) | SP1/RISC0 guest 输入和 public output 使用带 magic/tag 的紧凑二进制 codec。 | 替代 JSON 作为 guest 输入，减少输入体积和 decode 成本。 |
| KEM witness 定长 wrapper + zero-slot 压缩 | [`types.rs`](../crates/proof-core/src/types.rs#L7-L14), [`types.rs`](../crates/proof-core/src/types.rs#L16-L35), [`codec.rs`](../crates/proof-core/src/codec.rs#L656-L698) | `KemPublicKey` 固定 1184 bytes，`KemCiphertext` 固定 1088 bytes；codec 对全零 slot 用 tag `0`，非零 slot 用 tag `1 + bytes`。 | 既保留 ML-KEM 真实 witness，又避免空 batch slot 携带大段零字节。 |
| 四个 circuit 共用执行入口 | [`execute.rs`](../crates/proof-core/src/execute.rs#L6-L17) | `ProverInput` 分发到 `processMessages`、`tallyVotes`、`processDeactivate`、`addNewKey`。 | RISC0/SP1 guest 共享同一套 proof-core 逻辑，减少双实现偏差。 |
| full five-signup fixture | [`round_fixture.rs`](../crates/proof-core/src/round_fixture.rs#L21-L45), [`round_fixture.rs`](../crates/proof-core/src/round_fixture.rs#L109-L220) | 构造 `five-signup-2-1-1-5` round，包含 5 个初始 signup、1 个 replacement、5 条 vote message、2 批 tally。 | 覆盖真实 round 的 `processDeactivate -> addNewKey -> processMessages -> tally0 -> tally1` 闭环。 |
| SP1 compressed artifact 路径 | [`proof-sp1-host/src/main.rs`](../crates/proof-sp1-host/src/main.rs#L46-L60), [`proof-sp1-host/src/main.rs`](../crates/proof-sp1-host/src/main.rs#L78-L90), [`proof-sp1-host/src/main.rs`](../crates/proof-sp1-host/src/main.rs#L146-L160) | host CLI 支持 `prove-compressed` / `verify-compressed`，输出 raw proof bytes、public bytes、vkey。 | 产物可以直接组装成 CosmWasm `verify-compressed.msg.json` 提交链上。 |

这些优化不改变 AMACI 协议语义，主要是把实现从“SNARK/Circom-friendly”调整成“zkVM execution-friendly”。

#### 4.2.3 PQC 迁移具体替换了什么

PQC 迁移替换的是协议里的公钥密码组件，而不是替换 Merkle、tally、state transition 这些业务逻辑。

具体替换如下。这里的“迁移前”指早期非 PQ 签名 / 非 PQ shared-key 路径；当前分支已经把协议里的授权签名和 KEM/shared-key 组件替换为 ML-DSA-65 与 ML-KEM-768。

| 协议位置 | 迁移前 | 当前 PQC 版本 | 代码位置 | 协议作用 |
| --- | --- | --- | --- | --- |
| PQC crate 依赖入口 | 非 PQ 签名/KEM crate | `ml-dsa = 0.1.1`，`ml-kem = 0.3.2` | [`Cargo.toml`](../crates/proof-core/Cargo.toml#L6-L13) | proof-core 直接依赖 RustCrypto ML-DSA / ML-KEM，并关闭默认 feature，适配 zkVM guest。 |
| 用户 command 授权签名 | 非 PQ 签名路径 | ML-DSA-65 verify | [`auth.rs`](../crates/proof-core/src/auth.rs#L5-L12), [`auth.rs`](../crates/proof-core/src/auth.rs#L22-L40) | 校验 vote/deactivate command 由 state leaf 绑定的用户认证 key 授权。 |
| 用户认证 key commitment | 旧认证公钥 hash | ML-DSA public key domain-separated hash | [`auth.rs`](../crates/proof-core/src/auth.rs#L14-L20), [`round_fixture.rs`](../crates/proof-core/src/round_fixture.rs#L83-L95) | state leaf 第 10 个字段绑定 ML-DSA public key hash，proof 内用它约束签名公钥。 |
| 测试/fixture 签名生成 | 非 PQ test signer | ML-DSA-65 seed/keypair/sign | [`auth.rs`](../crates/proof-core/src/auth.rs#L46-L64), [`round_fixture.rs`](../crates/proof-core/src/round_fixture.rs#L67-L80) | five-signup fixture 里的每个用户都持有 ML-DSA auth key，用于生成可验证 command signature。 |
| coordinator / user compact public key | 非 PQ public key 派生 | ML-KEM public key compact 到 `[Field; 2]` | [`pq_kem.rs`](../crates/proof-core/src/pq_kem.rs#L18-L26), [`pq_kem.rs`](../crates/proof-core/src/pq_kem.rs#L65-L71), [`crypto.rs`](../crates/proof-core/src/crypto.rs#L8-L10) | AMACI 原协议里仍需要 `[Field; 2]` pubkey 位置；当前实现用 ML-KEM public key 的 compact commitment 填充。 |
| message shared key | 非 PQ ECDH/KEM 路径 | ML-KEM-768 decapsulation | [`pq_kem.rs`](../crates/proof-core/src/pq_kem.rs#L55-L63), [`process_messages.rs`](../crates/proof-core/src/circuits/process_messages.rs#L185-L200) | coordinator 用 private witness decapsulate 每条 message 的 ML-KEM ciphertext，得到 shared key 后解 command。 |
| message ciphertext commitment | compact `enc_pub_key` | ML-KEM ciphertext compact commitment | [`pq_kem.rs`](../crates/proof-core/src/pq_kem.rs#L65-L78), [`process_messages.rs`](../crates/proof-core/src/circuits/process_messages.rs#L191-L199) | message chain 里的 `enc_pub_key` 继续绑定每条 message 的加密材料，但底层换成 ML-KEM ciphertext commitment。 |
| processMessages command authorization | 非 PQ signature check | ML-DSA-65 signature check | [`process_messages.rs`](../crates/proof-core/src/circuits/process_messages.rs#L1-L4), [`process_messages.rs`](../crates/proof-core/src/circuits/process_messages.rs#L230-L240), [`auth.rs`](../crates/proof-core/src/auth.rs#L22-L40) | 解密 command 后继续校验用户授权签名，再执行 nonce、balance、vote weight、state update。 |
| processDeactivate authorization + user KEM key binding | 非 PQ signature/shared-key | ML-DSA-65 verify + ML-KEM public key compact | [`process_deactivate.rs`](../crates/proof-core/src/circuits/process_deactivate.rs#L180-L195), [`process_deactivate.rs`](../crates/proof-core/src/circuits/process_deactivate.rs#L203-L226), [`process_deactivate.rs`](../crates/proof-core/src/circuits/process_deactivate.rs#L243-L251) | deactivate command 必须由用户签名授权，并且 deactivate KEM public key 必须和 state leaf 中的 compact pubkey 一致。 |
| deactivate leaf shared key | 非 PQ shared key | ML-KEM-768 deterministic encapsulation | [`pq_kem.rs`](../crates/proof-core/src/pq_kem.rs#L28-L53), [`process_deactivate.rs`](../crates/proof-core/src/circuits/process_deactivate.rs#L252-L281), [`process_deactivate.rs`](../crates/proof-core/src/circuits/process_deactivate.rs#L318-L333) | proof 内证明 deactivate ciphertext、`c1/c2`、shared key hash 和新 deactivate leaf 一致。 |
| addNewKey 可打开性证明 | 非 PQ private key 打开路径 | ML-KEM-768 decapsulation | [`add_new_key.rs`](../crates/proof-core/src/circuits/add_new_key.rs#L19-L38), [`add_new_key.rs`](../crates/proof-core/src/circuits/add_new_key.rs#L39-L60) | 旧用户 private key 必须能 decapsulate deactivate ciphertext，重建 shared key hash 和 deactivate leaf，才能迁移到新 key。 |
| deactivate ciphertext 字段化 | 非 PQ c1/c2 | ML-KEM ciphertext compact 成 `c1/c2` | [`pq_kem.rs`](../crates/proof-core/src/pq_kem.rs#L73-L78), [`add_new_key.rs`](../crates/proof-core/src/circuits/add_new_key.rs#L19-L33) | 保留原协议中 `c1/c2` 作为 deactivate leaf 输入的结构，但其来源换成 ML-KEM ciphertext commitment。 |

更具体地说：

```text
processMessages:
  1. 校验 ML-DSA signature，证明 command 是用户授权的。
  2. 校验 KEM ciphertext compact == enc_pub_key。
  3. 用 coord_priv_key decapsulate ML-KEM ciphertext 得到 shared_key。
  4. 用 shared_key 解密 command。
  5. 继续执行 state update / vote weight update / nonce / balance 约束。

processDeactivate:
  1. 校验 ML-DSA signature，证明 deactivate command 是用户授权的。
  2. 校验 state leaf 中的 KEM public key compact。
  3. 用用户 KEM public key 和 randomness 生成 deactivate KEM ciphertext。
  4. 证明 c1/c2 来自该 deactivate KEM ciphertext。
  5. 证明 shared_key_hash 进入 deactivate leaf。

addNewKey:
  1. 用旧用户 private key decapsulate deactivate KEM ciphertext。
  2. 重建 shared_key_hash。
  3. 重建 deactivate leaf。
  4. 证明旧 key 的 deactivate leaf 存在，从而允许迁移到新 key。
```

所以当前 PQC 版本保留了原协议的关键约束：

```text
command 必须有用户授权
message 解密必须绑定 coordinator private witness
deactivate leaf 必须绑定用户 KEM public key
addNewKey 必须证明旧用户能打开 deactivate ciphertext
round stage 顺序和 commitment 链路不变
```

#### 4.2.4 当前 PQC 迁移没有做的事情

为了避免重新评估协议安全性，明确没有做这些协议级优化：

| 未做事项 | 原因 |
| --- | --- |
| 多条 message 共用一个 batch/session KEM | 会改变 key 隔离模型，单个 shared key 泄露影响范围变大。 |
| `processDeactivate` 不证明 KEM encapsulation，延迟到 `addNewKey` 再证明 | 会削弱 deactivate stage 自身完整性。 |
| 合并 processMessages / tally proof | 属于 proof aggregation 设计，会改变链上 verifier 调用模型，需要单独设计。 |
| 改变 vote/tally/state transition 业务规则 | 本轮目标是 primitive 替换，不改变 AMACI 协议业务语义。 |

所以，本轮报告里的 PQC E2E 结论可以理解为：

```text
在保持 AMACI round 协议语义不变的前提下，
签名和密钥交换/封装已经迁移到 ML-DSA / ML-KEM，
并完成 SP1 compressed proof + CosmWasm 合约验证闭环。
```

## 5. Proof 输入与产物

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
SP1 compressed vkey hash
```

本轮单个链上 execute msg 大小约为：

| Stage | execute msg bytes |
| --- | ---: |
| `processDeactivate` | 1,697,271 |
| `addNewKey` | 1,697,308 |
| `processMessagesFull` | 1,697,269 |
| `tally0` | 1,697,090 |
| `tally1` | 1,697,090 |

## 6. SP1 Proving / Execute 指标

高性能机器上，PQC fixed-size KEM 版本的 SP1 execute profile 结果：

| Stage | input bytes | public bytes | SP1 instructions | max RSS KB |
| --- | ---: | ---: | ---: | ---: |
| `processDeactivate` | 27,646 | 297 | 15,286,604 | 9,122,524 |
| `addNewKey` | 2,258 | 329 | 2,442,818 | 9,096,820 |
| `processMessagesFull` | 39,467 | 297 | 21,825,558 | 9,105,620 |
| `tally0` | 3,013 | 169 | 425,728 | 9,083,684 |
| `tally1` | 3,013 | 169 | 426,418 | 9,102,396 |

高性能机器上，PQC fixed-size KEM 版本的 SP1 compressed proving 结果：

| Stage | input bytes | public bytes | max RSS KB | raw proof bytes | bincode proof bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| `processDeactivate` | 27,646 | 297 | 60,588,032 | 1,272,546 | 1,272,866 |
| `addNewKey` | 2,258 | 329 | 20,949,764 | 1,272,546 | 1,272,898 |
| `processMessagesFull` | 39,467 | 297 | 64,288,144 | 1,272,546 | 1,272,866 |
| `tally0` | 3,013 | 169 | 16,016,632 | 1,272,546 | 1,272,738 |
| `tally1` | 3,013 | 169 | 17,074,256 | 1,272,546 | 1,272,738 |

结论：

```text
PQC 版 2-1-1-5 全部 stage 可以 compressed prove 成功。
单个 compressed proof raw size 稳定在约 1.27 MB。
processMessagesFull 和 processDeactivate 是 prover 侧资源瓶颈。
processMessagesFull compressed proving 峰值约 64.3GB KB 口径，即约 61.3 GiB RSS。
```

## 7. CosmWasm 合约实现

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

```text
没有 round 时间窗口
没有 admin/operator 权限控制
没有 signup/vote period 检查
没有用户押金、注册、投票入口等完整业务状态机
```

合约验证 proof 有效性和 stage 顺序；AMACI 业务语义由 zkVM proof 内部的 Rust 逻辑保证。

## 8. 链上执行结果

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
dora1pvrwmjuusn9wh34j7y520g8gumuy9xtl3gvprlljfdpwju3x7ucsp60ag2
```

## 9. Gas 与 DORA 成本

| 步骤 | 高度 | Gas wanted | Gas used | 估算 DORA | 交易哈希 |
| --- | ---: | ---: | ---: | ---: | --- |
| store code | 35771 | 3,822,887 | 3,476,962 | 0.034769620 | `481AC8296927809B6C4A4C6AB2FEC8182642A8BCCF79D3087DC806017D35469F` |
| instantiate round | 35772 | 196,866 | 142,222 | 0.001422220 | `939011C87A559117D70B1E3D819D96524D0372F22A0546E35E3636F9DC42F687` |
| processDeactivate | 35773 | 300,000,000 | 20,338,714 | 0.203387140 | `B1F42AD9411C95B0CDCF56678606726D3F8AB58270548312E84BB90E11177EAF` |
| addNewKey | 35774 | 300,000,000 | 20,339,006 | 0.203390060 | `836837D9472FA897841C42E6BCC7644E0A7BE7892C8B9120BD2B59B817F4080A` |
| processMessagesFull | 35775 | 300,000,000 | 20,338,660 | 0.203386600 | `D4BD968CF1066CCC4DBB62B2F33679C7BFEE39CD4DA3B51B5CEA3A425B671F80` |
| tally0 | 35776 | 300,000,000 | 20,336,637 | 0.203366370 | `17A727E7034FCB9BAF2D1FA5C7E0032D4DDFD4270F6038F56361FE1B49B839AE` |
| tally1 | 35777 | 300,000,000 | 20,336,630 | 0.203366300 | `3068FC3CBD5542AF23871F3221DD94E011E70C0878D7BDCD2F8DCD9B63EC6ACB` |

总估算成本：

```text
1.053088310 DORA
```

只计算 5 个 proof verify，不包含 store code 和 instantiate：

```text
1.016896470 DORA
```

平均单个 compressed proof verify 成本：

```text
0.203379294 DORA
```

说明：

```text
本地 devnet 实际 signGasPricePeaka = 0。
上面的 DORA 成本按 costGasPricePeaka = 10000000000 peaka/gas 估算。
```

## 10. 验证命令

构建 round 合约：

```bash
npm run build:round-contract
```

执行真实 five-signup PQC E2E：

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

## 11. 后续优化方向

本轮已经完成：

```text
PQC 签名层 ML-DSA-65 E2E 验证
PQC KEM 层 ML-KEM-768 E2E 验证
SP1 compressed proof 生成
本地 SP1 compressed verifier 验证
CosmWasm 合约逐 stage 链上验证
完整 AMACI five-signup round 状态闭环
```

当前主要瓶颈：

```text
prover 侧: processMessagesFull / processDeactivate 的 SP1 compressed proving 内存接近 64GB 机器边界
链上侧: 单个 SP1 compressed proof verify 约 20.34M gas，round 总成本随 proof 数量线性增长
```

后续优先级：

1. 先用 `scripts/run_sp1_crypto_profile.sh` 拆解 ML-KEM decap、ML-KEM encap、ML-DSA verify、KEM compact、command decrypt 的 SP1 execute 指令成本。
2. 根据 profile 结果做 prover 侧热点优化。
3. 在大规模 round 场景下，优先设计 `processMessages_*` 和 `tally_*` proof aggregation，降低链上 verify 次数，所以更关键的是 proof aggregation。
