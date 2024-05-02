<script setup lang="ts">
import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509';
import { bech32m } from 'bech32';
import elliptic from 'elliptic';
import { useIntervalFn, useStorage } from '@vueuse/core'
import { toCoinId, type Coin, type CoinSpend, SpendBundle } from 'chia-rpc';
import { Program } from 'clvm-lib';

import p2ConditionsHex from '~/puzzles/p2_conditions.clsp.hex?raw';
import p2DelegatedPuzzleOrHiddenPasskeyPuzzleHex from '~/puzzles/p2_delegated_or_hidden_passkey.clsp.hex?raw';

/* eslint-disable import/no-named-as-default-member */
const p256 = new elliptic.ec('p256');
/* eslint-enable import/no-named-as-default-member */

const PASSKEY_PUZZLE_MOD = Program.deserializeHex(p2DelegatedPuzzleOrHiddenPasskeyPuzzleHex);
const P2_CONDITIONS_MOD = Program.deserializeHex(p2ConditionsHex);

// const MAINNET_GENESIS_CHALLENGE = Program.deserializeHex(
//   'ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb'
// );
const TESTNET11_GENESIS_CHALLENGE = Program.fromHex('37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615');
const DEFAULT_HIDDEN_PUZZLE_HASH = Program.fromBytes(Program.deserializeHex('ff0980').hash());

function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  let pointer = 0;
  const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);

  const toReturn = new Uint8Array(totalLength);

  arrays.forEach((arr) => {
    toReturn.set(arr, pointer);
    pointer += arr.length;
  });

  return toReturn;
}

function fromHex(hex: string) {
  return new Uint8Array(hex.match(/../g)!.map(h => parseInt(h, 16)))

}

function toHex(buffer: ArrayBuffer) {
  return new Uint8Array(buffer).reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

function arrayBufferToBase64(buffer: ArrayBuffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function findIndexOfArray(parentArray: Uint8Array, childArray: Uint8Array) {
  if (childArray.length === 0) return -1;
  for (let i = 0; i <= parentArray.length - childArray.length; i++) {
    let found = true;
    for (let j = 0; j < childArray.length; j++) {
      if (parentArray[i + j] !== childArray[j]) {
        found = false;
        break;
      }
    }
    if (found) return i;
  }
  return -1;
}

function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

const credentials = useStorage<
    Record<
        string,
        {
          publicKey: string;
          puzzleHash: string;
          address: string;
        }
    >
>('credentials', {});

const generateWallet = async () => {
  const encoder = new TextEncoder();

  const username = 'example';

  // Registration options
  const options: CredentialCreationOptions = {
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: {
        name: 'MintGarden',
        id: window.location.hostname,
      },
      user: {
        id: await crypto.subtle.digest('sha-256', encoder.encode('username:' + username)),
        name: username,
        displayName: username,
      },
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required',
      },
    },
  };

  try {
    // Ask the browser to create / register a credential
    const regCredential = (await navigator.credentials.create(options)) as PublicKeyCredential | null;
    const credentialId = regCredential!.id;
    const response = regCredential!.response as AuthenticatorAttestationResponse;
    const pkBytes = response.getPublicKey();
    // const derEncodedPublicKey = toHex(pkBytes);
    const result = AsnParser.parse(pkBytes!, SubjectPublicKeyInfo);
    // const decodedPublicKey = toHex(result.subjectPublicKey);
    // const pubKey = p256.keyFromPublic(decodedPublicKey, 'hex');
    const pubKey = p256.keyFromPublic(result.subjectPublicKey);
    const compressedPubkey = pubKey.getPublic().encodeCompressed('hex');
    console.log('public key', compressedPubkey);

    const p2Puzzle = PASSKEY_PUZZLE_MOD.curry([
      TESTNET11_GENESIS_CHALLENGE,
      Program.fromHex(compressedPubkey),
      DEFAULT_HIDDEN_PUZZLE_HASH,
    ]);
    const puzzleHash = p2Puzzle.hash();
    console.log('puzzle hash', toHex(puzzleHash));
    console.log(
        'address',
        bech32m.encode('txch', bech32m.toWords(puzzleHash))
    );

    credentials.value[credentialId] = {
      publicKey: compressedPubkey,
      puzzleHash: toHex(puzzleHash),
      address: bech32m.encode('txch', bech32m.toWords(puzzleHash)),
    };
  } catch (e) {
    console.log(e);
  }
};

const recoverWallet = async () => {
  async function discoverPublicKeys() {
    const options: CredentialRequestOptions = {
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
        userVerification: 'required',
        timeout: 5000,
      },
    };

    const regCredential = (await navigator.credentials.get(options)) as PublicKeyCredential | null;
    const credentialId = regCredential!.id;
    const response = regCredential!.response as AuthenticatorAssertionResponse;

    // Recovery: Do this two times, and see which public key stays the same
    const bufferToDecimal = (x) => p256.keyFromPrivate(x, 'hex').getPrivate().toString(10);
    const clientDataJSONHash = await window.crypto.subtle.digest('SHA-256', response.clientDataJSON);

    const msg = concatUint8Arrays([new Uint8Array(response.authenticatorData), new Uint8Array(clientDataJSONHash)]);

    const msgHash = toHex(await window.crypto.subtle.digest('SHA-256', msg));

    const parsedSignature = AsnParser.parse(response.signature, ECDSASigValue);
    return {
      credentialId,
      publicKeys: [0, 1].map((i) =>
          p256.recoverPubKey(bufferToDecimal(msgHash), parsedSignature, i).encodeCompressed('hex')
      ),
    };
  }

  try {
    const { publicKeys } = await discoverPublicKeys();
    const { credentialId, publicKeys: publicKeys2 } = await discoverPublicKeys();
    const publicKey = publicKeys.find((x) => publicKeys2.includes(x));

    const p2Puzzle = PASSKEY_PUZZLE_MOD.curry([
      TESTNET11_GENESIS_CHALLENGE,
      Program.fromHex(publicKey),
      DEFAULT_HIDDEN_PUZZLE_HASH,
    ]);
    const puzzleHash = p2Puzzle.hash();
    console.log('puzzle hash', toHex(puzzleHash));
    console.log(
        'address',
        bech32m.encode('txch', bech32m.toWords(puzzleHash))
    );

    credentials.value[credentialId] = {
      publicKey,
      puzzleHash: toHex(puzzleHash),
      address: bech32m.encode('txch', bech32m.toWords(puzzleHash)),
    };
  } catch (e) {
    console.log(e);
  }
};

function decodeSignature(response: AuthenticatorAssertionResponse): string {
  const parsedSignature = AsnParser.parse(response.signature, ECDSASigValue);
  let rBytes = new Uint8Array(parsedSignature.r);
  let sBytes = new Uint8Array(parsedSignature.s);
  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1);
  }
  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1);
  }
  const finalSignature = concatUint8Arrays([rBytes, sBytes]);
  return toHex(finalSignature);
}

const signAndSubmitTransferTransaction = async () => {
  sendResultMessage.value = '';

  try {
    const utxos = await $fetch<{ parent_coin_info: string; puzzle_hash: string; amount: string }[]>(
        `/api/utxos?address=${address.value}&chain=testnet11`
    );
    const coin: Coin = {
      parent_coin_info: utxos[0].parent_coin_info,
      puzzle_hash: utxos[0].puzzle_hash,
      amount: parseInt(utxos[0].amount),
    };
    const targetPuzzleHash = toHex(new Uint8Array(bech32m.fromWords(bech32m.decode(target.value).words)));
    const createCoinCondition = Program.fromList([
      Program.fromInt(51),
      Program.fromBytes(fromHex(targetPuzzleHash)),
      Program.fromInt(coin.amount),
      Program.fromList([]),
    ]);
    const conditions = [createCoinCondition];

    const delegatedPuzzle = P2_CONDITIONS_MOD.run(Program.fromList([Program.fromList(conditions)])).value;
    const delegatedSolution = Program.fromInt(0);
    const coinId = toCoinId(coin);
    const challenge = concatUint8Arrays([
      delegatedPuzzle.hash(),
      coinId,
      TESTNET11_GENESIS_CHALLENGE.toBytes(),
      DEFAULT_HIDDEN_PUZZLE_HASH.toBytes(),
    ]);
    const challengeHash = await window.crypto.subtle.digest('sha-256', challenge);

    const options: CredentialRequestOptions = {
      publicKey: {
        challenge: challengeHash,
        rpId: window.location.hostname,
        userVerification: 'required',
      },
    };

    // Ask the browser to sign a message using a passkey
    const credential = (await navigator.credentials.get(options)) as PublicKeyCredential | null;
    if (!credential) {
      throw new Error('No credential found');
    }

    const response = credential.response as AuthenticatorAssertionResponse;

    const clientDataJson = toHex(response.clientDataJSON);
    const authenticatorData = toHex(response.authenticatorData);

    const signature = decodeSignature(response);

    const challengeHashBase64 = arrayBufferToBase64(challengeHash)
        .replaceAll('/', '_')
        .replaceAll('+', '-')
        .replaceAll('=', '');

    const index = findIndexOfArray(new Uint8Array(response.clientDataJSON), new TextEncoder().encode('"challenge":"' + challengeHashBase64 + '"'));

    console.log({ index });
    if (index === -1) {
      throw new Error('Could not find challenge in client data');
    }

    const publicKey = credentials.value[credential.id].publicKey;

    const puzzle = PASSKEY_PUZZLE_MOD.curry([
      TESTNET11_GENESIS_CHALLENGE,
      Program.fromHex(publicKey),
      DEFAULT_HIDDEN_PUZZLE_HASH,
    ]);

    const solution = Program.fromList([
      Program.fromHex(authenticatorData),
      Program.fromHex(clientDataJson),
      Program.fromInt(index),
      delegatedPuzzle,
      delegatedSolution,
      Program.fromHex(signature),
      Program.fromBytes(coinId)
    ]);

    const coinSpend: CoinSpend = {
      coin,
      puzzle_reveal: puzzle.serializeHex(),
      solution: solution.serializeHex(),
    };
    const spendBundle: SpendBundle = {
      coin_spends: [coinSpend],
      aggregated_signature: '0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    };
    console.log(spendBundle);

    const result = await $fetch<any>(`/api/sendtx?chain=testnet11`, {
      method: 'POST',
      body: { spend_bundle: spendBundle },
    });
    console.log(result);
    if (result?.status === 'SUCCESS') {
      sendResultMessage.value = 'Transaction submitted successfully!';
    } else {
      sendResultMessage.value = `Error: ${result?.detail || result}`;
    }
  } catch (e: any) {
    console.error(e);
    sendResultMessage.value = `Error: ${e}`;
  }
};


const address = computed(() => {
  const firstKey = Object.keys(credentials.value)[0];
  return credentials.value[firstKey]?.address || null;
});

const utxos = ref([]);
const target = ref('');
const sendResultMessage = ref('');

const balance = computed(() => {
  if (utxos.value) {
    return utxos.value.reduce((acc, utxo) => ({ amount: acc.amount + utxo.amount, coin_num: acc.coin_num + 1 }), {
      amount: 0,
      coin_num: 0,
    });
  }
  return { amount: 0, coin_num: 0 };
});

async function fetchBalance() {
  if (!address.value) {
    utxos.value = [];
    return;
  }
  const result = await $fetch<any>(`/api/utxos?address=${address.value}&chain=testnet11`);
  utxos.value = result.map((utxo) => ({ ...utxo, amount: parseInt(utxo.amount) }));
}

fetchBalance();

useIntervalFn(async () => {
  if (address.value) {
    await fetchBalance();
  }
}, 10000);
</script>
<template>
  <div class="mx-auto mt-16 flex max-w-xl flex-col gap-4 whitespace-nowrap dark:text-white">
    <div class="text-2xl font-bold">Testnet11 Passkey Wallet</div>

    <template v-if="address">
      <div>
        Address: <span class="font-mono">{{ address }}</span>
      </div>
      <div>Balance: {{ balance?.amount }} mojos, {{ balance?.coin_num }} coins</div>

      <div class="flex flex-col gap-2">
        <div class="text-xl font-bold">Transfer coin</div>
        <div class="flex gap-1 items-center">
          Target Address:
          <input
              class="w-full border-0 px-2 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 sm:text-sm sm:leading-6"
              v-model="target"
              type="text"
              placeholder="txch1..."
          />
        </div>
        <div>Amount: {{ utxos[0]?.amount || 'No coin available' }}</div>

        <button class="border p-4" @click="signAndSubmitTransferTransaction">Transfer</button>
        <div v-if="sendResultMessage">{{ sendResultMessage }}</div>
      </div>
    </template>
    <template v-else>
      <button class="border p-4" @click="generateWallet">Create Wallet</button>
      <button class="border p-4" @click="recoverWallet">Recover Wallet</button>
    </template>
  </div>
</template>
