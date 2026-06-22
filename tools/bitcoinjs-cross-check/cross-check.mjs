import { BIP32Factory } from 'bip32';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import * as ecc from 'tiny-secp256k1';

const bip32 = BIP32Factory(ecc);
const ECPair = ECPairFactory(ecc);

const DOGECOIN_NETWORKS = {
  mainnet: {
    messagePrefix: '\x19Dogecoin Signed Message:\n',
    bech32: '',
    pubKeyHash: 30,
    scriptHash: 22,
    wif: 158,
    bip32: {
      public: 0x02facafd,
      private: 0x02fac398,
    },
  },
  testnet: {
    messagePrefix: '\x19Dogecoin Signed Message:\n',
    bech32: '',
    pubKeyHash: 113,
    scriptHash: 196,
    wif: 241,
    bip32: {
      public: 0x043587cf,
      private: 0x04358394,
    },
  },
  regtest: {
    messagePrefix: '\x19Dogecoin Signed Message:\n',
    bech32: '',
    pubKeyHash: 111,
    scriptHash: 196,
    wif: 239,
    bip32: {
      public: 0x043587cf,
      private: 0x04358394,
    },
  },
};

async function main() {
  const args = process.argv.slice(2);
  if (args[0] === '--') {
    args.shift();
  }
  const [inputPath, outputPath] = args;
  if (!inputPath || !outputPath) {
    throw new Error('usage: node cross-check.mjs <input.json> <output.json>');
  }

  const input = JSON.parse(await readFile(inputPath, 'utf8'));
  const mnemonicById = new Map(input.mnemonics.map((mnemonic) => [mnemonic.id, mnemonic]));
  const bip44ById = new Map(input.bip44_cases.map((bip44Case) => [bip44Case.id, bip44Case]));
  const mnemonics = Object.fromEntries(
    input.mnemonics.map((mnemonic) => [mnemonic.id, emitMnemonic(mnemonic)]),
  );
  const bip44Cases = input.bip44_cases.map((bip44Case) => {
    const mnemonic = mnemonicById.get(bip44Case.mnemonic_id);
    if (!mnemonic) {
      throw new Error(`unknown mnemonic case ${bip44Case.mnemonic_id}`);
    }
    return emitBip44Case(bip44Case, mnemonic);
  });
  const messageCases = input.message_cases.map((messageCase) =>
    emitMessageCase(messageCase, mnemonicById, bip44ById),
  );
  const transactionCases = input.transaction_cases.map((transactionCase) =>
    emitTransactionCase(transactionCase, mnemonicById, bip44ById),
  );
  const multisigCases = input.multisig_cases.map((multisigCase) =>
    emitMultisigCase(multisigCase, mnemonicById, bip44ById),
  );

  const output = {
    version: input.version,
    mnemonics,
    bip44_cases: bip44Cases,
    message_cases: messageCases,
    transaction_cases: transactionCases,
    multisig_cases: multisigCases,
  };

  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(output, null, 2)}\n`);
}

function emitMnemonic(mnemonic) {
  return {
    id: mnemonic.id,
    language: mnemonic.language,
    valid: bip39.validateMnemonic(mnemonic.phrase),
    seed_hex: bip39.mnemonicToSeedSync(mnemonic.phrase, mnemonic.passphrase).toString('hex'),
  };
}

function emitBip44Case(bip44Case, mnemonic) {
  const network = networkFor(bip44Case.network);
  const seed = bip39.mnemonicToSeedSync(mnemonic.phrase, mnemonic.passphrase);
  const root = bip32.fromSeed(seed, network);
  const accountPath = `m/44'/3'/${bip44Case.account}'`;
  const account = deriveRelativePath(root, accountPath);
  const accountXpub = account.neutered();

  return {
    id: bip44Case.id,
    mnemonic_id: bip44Case.mnemonic_id,
    network: bip44Case.network,
    account: bip44Case.account,
    account_path: accountPath,
    account_xpriv: account.toBase58(),
    account_xpub: accountXpub.toBase58(),
    children: bip44Case.child_paths.map((childPath) =>
      emitChild(childPath, account, accountXpub, network),
    ),
    hardened_public_derivation: emitHardenedRejection(
      bip44Case.hardened_public_path,
      accountXpub,
    ),
  };
}

function emitChild(childPath, account, accountXpub, network) {
  const childXpriv = deriveRelativePath(account, childPath);
  const childXpub = deriveRelativePath(accountXpub, childPath);
  const childXpubFromXpriv = childXpriv.neutered();
  const privateAddress = p2pkhAddress(childXpriv.publicKey, network);
  const publicAddress = p2pkhAddress(childXpub.publicKey, network);
  const wif = ECPair.fromPrivateKey(Buffer.from(childXpriv.privateKey), {
    compressed: true,
    network,
  }).toWIF();
  const wifImport = ECPair.fromWIF(wif, network);

  return {
    path: childPath,
    xpriv: childXpriv.toBase58(),
    xpub: childXpub.toBase58(),
    xpub_from_xpriv: childXpubFromXpriv.toBase58(),
    public_key_hex_from_xpriv: toHex(childXpriv.publicKey),
    public_key_hex_from_xpub: toHex(childXpub.publicKey),
    address_from_xpriv: privateAddress,
    address_from_xpub: publicAddress,
    wif,
    wif_import: {
      public_key_hex: toHex(wifImport.publicKey),
      address: p2pkhAddress(wifImport.publicKey, network),
      compressed: wifImport.compressed,
    },
  };
}

function emitHardenedRejection(pathValue, accountXpub) {
  try {
    deriveRelativePath(accountXpub, pathValue);
    return {
      path: pathValue,
      rejected: false,
      error_kind: null,
    };
  } catch (error) {
    if (error instanceof HardenedPublicDerivationError) {
      return {
        path: pathValue,
        rejected: true,
        error_kind: 'hardened-public-derivation',
      };
    }
    throw error;
  }
}

function emitMessageCase(messageCase, mnemonicById, bip44ById) {
  const { networkName, network, account } = accountForCase(
    messageCase.bip44_case_id,
    mnemonicById,
    bip44ById,
  );
  const signer = deriveRelativePath(account, messageCase.signer_path);
  const wif = ECPair.fromPrivateKey(Buffer.from(signer.privateKey), {
    compressed: true,
    network,
  }).toWIF();
  const signature = signDogecoinMessage(wif, network, messageCase.message);

  return {
    id: messageCase.id,
    bip44_case_id: messageCase.bip44_case_id,
    signer_path: messageCase.signer_path,
    message: messageCase.message,
    network: networkName,
    address: signature.address,
    signature_base64: signature.signature_base64,
    verified: verifyDogecoinMessage(
      network,
      signature.address,
      signature.signature_base64,
      messageCase.message,
    ),
  };
}

function emitTransactionCase(transactionCase, mnemonicById, bip44ById) {
  const { networkName, network, account } = accountForCase(
    transactionCase.bip44_case_id,
    mnemonicById,
    bip44ById,
  );
  const signer = deriveRelativePath(account, transactionCase.signer_path);
  const publicKey = Buffer.from(signer.publicKey);
  const scriptPubkey = p2pkhScriptPubkey(publicKey);
  const tx = bitcoin.Transaction.fromHex(transactionCase.unsigned_tx_hex);
  const sighash = tx.hashForSignature(
    transactionCase.input_index,
    scriptPubkey,
    transactionCase.sighash_type,
  );
  const signature = ecc.sign(sighash, Buffer.from(signer.privateKey));
  const signatureWithHashType = bitcoin.script.signature.encode(
    Buffer.from(signature),
    transactionCase.sighash_type,
  );
  const scriptSig = bitcoin.script.compile([signatureWithHashType, publicKey]);
  tx.setInputScript(transactionCase.input_index, scriptSig);

  return {
    id: transactionCase.id,
    bip44_case_id: transactionCase.bip44_case_id,
    signer_path: transactionCase.signer_path,
    network: networkName,
    unsigned_tx_hex: transactionCase.unsigned_tx_hex,
    input_index: transactionCase.input_index,
    sighash_type: transactionCase.sighash_type,
    script_pubkey_hex: toHex(scriptPubkey),
    public_key_hex: toHex(publicKey),
    address: p2pkhAddress(publicKey, network),
    signed_tx_hex: tx.toHex(),
  };
}

function emitMultisigCase(multisigCase, mnemonicById, bip44ById) {
  const network = networkFor(multisigCase.network);
  let publicKeys = multisigCase.cosigner_bip44_case_ids.map((caseId) => {
    const { networkName, account } = accountForCase(caseId, mnemonicById, bip44ById);
    if (networkName !== multisigCase.network) {
      throw new Error(`cosigner xpub network mismatch for ${caseId}`);
    }
    const child = deriveRelativePath(account.neutered(), multisigCase.child_path);
    return Buffer.from(child.publicKey);
  });
  if (multisigCase.sorted) {
    publicKeys = publicKeys.sort(Buffer.compare);
  }
  const redeemScript = bitcoin.payments.p2ms({
    m: multisigCase.threshold,
    pubkeys: publicKeys,
    network,
  }).output;
  const p2sh = bitcoin.payments.p2sh({ redeem: { output: redeemScript }, network });

  return {
    id: multisigCase.id,
    network: multisigCase.network,
    threshold: multisigCase.threshold,
    cosigner_count: multisigCase.cosigner_bip44_case_ids.length,
    cosigner_bip44_case_ids: multisigCase.cosigner_bip44_case_ids,
    child_path: multisigCase.child_path,
    sorted: multisigCase.sorted,
    public_keys_hex: publicKeys.map(toHex),
    redeem_script_hex: toHex(redeemScript),
    p2sh_address: p2sh.address,
  };
}

function accountForCase(caseId, mnemonicById, bip44ById) {
  const bip44Case = bip44ById.get(caseId);
  if (!bip44Case) {
    throw new Error(`unknown BIP44 case ${caseId}`);
  }
  const mnemonic = mnemonicById.get(bip44Case.mnemonic_id);
  if (!mnemonic) {
    throw new Error(`unknown mnemonic case ${bip44Case.mnemonic_id}`);
  }
  const network = networkFor(bip44Case.network);
  const seed = bip39.mnemonicToSeedSync(mnemonic.phrase, mnemonic.passphrase);
  const root = bip32.fromSeed(seed, network);
  const accountPath = `m/44'/3'/${bip44Case.account}'`;
  return {
    networkName: bip44Case.network,
    network,
    account: deriveRelativePath(root, accountPath),
  };
}

function signDogecoinMessage(wif, network, message) {
  const keyPair = ECPair.fromWIF(wif, network);
  const digest = dogecoinMessageDigest(message);
  const { signature, recoveryId } = ecc.signRecoverable(digest, Buffer.from(keyPair.privateKey));
  const compact = Buffer.alloc(65);
  compact[0] = 27 + 4 + recoveryId;
  Buffer.from(signature).copy(compact, 1);
  return {
    address: p2pkhAddress(keyPair.publicKey, network),
    signature_base64: compact.toString('base64'),
  };
}

function verifyDogecoinMessage(network, address, signatureBase64, message) {
  const compact = Buffer.from(signatureBase64, 'base64');
  if (compact.length !== 65) {
    return false;
  }
  const recoveryId = (compact[0] - 27) & 0x03;
  const digest = dogecoinMessageDigest(message);
  const publicKey = ecc.recover(digest, compact.subarray(1), recoveryId, true);
  return publicKey ? p2pkhAddress(publicKey, network) === address : false;
}

function dogecoinMessageDigest(message) {
  return bitcoin.crypto.hash256(
    Buffer.concat([
      varString(Buffer.from('Dogecoin Signed Message:\n', 'utf8')),
      varString(Buffer.from(message, 'utf8')),
    ]),
  );
}

function varString(bytes) {
  return Buffer.concat([varInt(bytes.length), bytes]);
}

function varInt(value) {
  if (value < 0xfd) {
    return Buffer.from([value]);
  }
  if (value <= 0xffff) {
    const buffer = Buffer.alloc(3);
    buffer[0] = 0xfd;
    buffer.writeUInt16LE(value, 1);
    return buffer;
  }
  if (value <= 0xffffffff) {
    const buffer = Buffer.alloc(5);
    buffer[0] = 0xfe;
    buffer.writeUInt32LE(value, 1);
    return buffer;
  }
  const buffer = Buffer.alloc(9);
  buffer[0] = 0xff;
  buffer.writeBigUInt64LE(BigInt(value), 1);
  return buffer;
}

function p2pkhScriptPubkey(publicKey) {
  return bitcoin.payments.p2pkh({ pubkey: Buffer.from(publicKey) }).output;
}

function deriveRelativePath(node, pathValue) {
  return pathSegments(pathValue).reduce((current, segment) => {
    const { index, hardened } = parsePathSegment(segment);
    if (hardened) {
      if (!current.privateKey) {
        throw new HardenedPublicDerivationError(pathValue);
      }
      return current.deriveHardened(index);
    }
    return current.derive(index);
  }, node);
}

function pathSegments(pathValue) {
  if (pathValue === 'm' || pathValue === '') {
    return [];
  }
  return pathValue.replace(/^m\//, '').split('/').filter(Boolean);
}

function parsePathSegment(segment) {
  const hardened = /['hH]$/.test(segment);
  const value = hardened ? segment.slice(0, -1) : segment;
  if (!/^\d+$/.test(value)) {
    throw new Error(`invalid derivation path segment: ${segment}`);
  }
  const index = Number(value);
  if (!Number.isSafeInteger(index) || index < 0 || index >= 0x80000000) {
    throw new Error(`derivation path index out of range: ${segment}`);
  }
  return { index, hardened };
}

function p2pkhAddress(publicKey, network) {
  return bitcoin.payments.p2pkh({ pubkey: Buffer.from(publicKey), network }).address;
}

function networkFor(name) {
  const network = DOGECOIN_NETWORKS[name];
  if (!network) {
    throw new Error(`unknown Dogecoin network: ${name}`);
  }
  return network;
}

function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

class HardenedPublicDerivationError extends Error {}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
