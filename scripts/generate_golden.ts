import fs from 'node:fs';
import path from 'node:path';

import {
  OperatorClient,
  VoterClient,
  Tree,
  computeInputHash,
  encryptOdevity,
  poseidon,
  rerandomize
} from '@dorafactory/maci-sdk';

import { circomkitInstance } from '../../packages/circuits/ts/__tests__/utils/utils';

const repoRoot = path.resolve(__dirname, '../..');
const outDir = path.join(repoRoot, 'zkvm-amaci/tests/golden');
const validateCircomkitWitness = process.env.VALIDATE_CIRCOMKIT_WITNESS === '1';

function bigintReplacer(_key: string, value: unknown) {
  return typeof value === 'bigint' ? value.toString() : value;
}

async function writeJson(name: string, value: unknown) {
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, name), JSON.stringify(value, bigintReplacer, 2) + '\n');
}

async function generateProcessDeactivate() {
  const stateTreeDepth = 2;
  const batchSize = 5;
  const treeArity = 5;
  const pollId = 1;

  const operator = new OperatorClient({ network: 'testnet', secretKey: 123456n });
  operator.initRound({
    stateTreeDepth,
    intStateTreeDepth: 1,
    voteOptionTreeDepth: 2,
    batchSize,
    maxVoteOptions: 5,
    pollId,
    isQuadraticCost: true,
    isAmaci: true
  });

  const voter = new VoterClient({ network: 'testnet', secretKey: 222222n });
  operator.updateStateTree(0, voter.getPubkey().toPoints(), 100);

  const deactivatePayload = voter.buildDeactivatePayload({
    stateIdx: 0,
    operatorPubkey: operator.getPubkey().toPoints(),
    pollId
  });
  operator.pushDeactivateMessage(
    deactivatePayload.msg.map(BigInt),
    deactivatePayload.encPubkeys.map(BigInt) as [bigint, bigint]
  );

  const result = await operator.processDeactivateMessages({
    inputSize: 1,
    subStateTreeLength: treeArity ** stateTreeDepth
  });

  if (validateCircomkitWitness) {
    const circuit = await circomkitInstance.WitnessTester('ProcessDeactivateMessages', {
      file: 'amaci/power/processDeactivate',
      template: 'ProcessDeactivateMessages',
      params: [stateTreeDepth, batchSize]
    });
    const witness = await circuit.calculateWitness(result.input as any);
    await circuit.expectConstraintPass(witness);
  }

  await writeJson('process_deactivate_2_5_valid.json', {
    circuit: 'ProcessDeactivateMessages',
    params: { stateTreeDepth, batchSize },
    input: result.input
  });
}

async function generateAddNewKey() {
  const stateTreeDepth = 2;
  const deactivateTreeDepth = stateTreeDepth + 2;
  const pollId = 1n;

  const operator = new OperatorClient({ network: 'testnet', secretKey: 123456n });
  const oldVoter = new VoterClient({ network: 'testnet', secretKey: 222222n });
  const newVoter = new VoterClient({ network: 'testnet', secretKey: 333333n });

  const coordPubKey = operator.getSigner().getPublicKey().toPoints() as [bigint, bigint];
  const oldSigner = oldVoter.getSigner();
  const oldPubKey = oldSigner.getPublicKey().toPoints() as [bigint, bigint];
  const oldPrivateKey = oldSigner.getFormatedPrivKey();
  const newPubKey = newVoter.getPubkey().toPoints() as [bigint, bigint];

  const sharedKeyHash = poseidon(operator.getSigner().genEcdhSharedKey(oldPubKey));
  const deactivateRandomVal = 444444444n;
  const deactivate = encryptOdevity(false, coordPubKey, deactivateRandomVal);
  const deactivateLeafRaw = [
    deactivate.c1.x,
    deactivate.c1.y,
    deactivate.c2.x,
    deactivate.c2.y,
    sharedKeyHash
  ];

  const tree = new Tree(5, deactivateTreeDepth, 0n);
  tree.initLeaves([poseidon(deactivateLeafRaw)]);

  const c1 = [deactivateLeafRaw[0], deactivateLeafRaw[1]] as [bigint, bigint];
  const c2 = [deactivateLeafRaw[2], deactivateLeafRaw[3]] as [bigint, bigint];
  const randomVal = 777777777n;
  const { d1, d2 } = rerandomize(coordPubKey, { c1, c2 }, randomVal);
  const nullifier = poseidon([oldPrivateKey, pollId]);

  const input = {
    inputHash: computeInputHash([
      tree.root,
      poseidon(coordPubKey),
      nullifier,
      d1[0],
      d1[1],
      d2[0],
      d2[1],
      poseidon(newPubKey),
      pollId
    ]),
    coordPubKey,
    deactivateRoot: tree.root,
    deactivateIndex: 0n,
    deactivateLeaf: poseidon(deactivateLeafRaw),
    c1,
    c2,
    randomVal,
    d1,
    d2,
    deactivateLeafPathElements: tree.pathElementOf(0),
    nullifier,
    oldPrivateKey,
    newPubKey,
    pollId
  };

  if (validateCircomkitWitness) {
    const circuit = await circomkitInstance.WitnessTester('AddNewKey', {
      file: 'amaci/power/addNewKey',
      template: 'AddNewKey',
      params: [stateTreeDepth]
    });
    const witness = await circuit.calculateWitness(input as any);
    await circuit.expectConstraintPass(witness);
  }

  await writeJson('add_new_key_2_valid.json', {
    circuit: 'AddNewKey',
    params: { stateTreeDepth },
    input
  });
}

async function main() {
  await generateProcessDeactivate();
  await generateAddNewKey();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
