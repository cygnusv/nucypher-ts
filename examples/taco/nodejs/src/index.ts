import { format } from 'node:util';

import {
  ThresholdMessageKit,
  conditions,
  decrypt,
  domains,
  encrypt,
  fromBytes,
  initialize,
  toBytes,
  toHexString,
} from '@nucypher/taco';
import {
  EIP4361AuthProvider,
  USER_ADDRESS_PARAM_DEFAULT,
} from '@nucypher/taco-auth';
import * as dotenv from 'dotenv';
import { ethers } from 'ethers';

dotenv.config();

const rpcProviderUrl = process.env.RPC_PROVIDER_URL;
if (!rpcProviderUrl) {
  throw new Error('RPC_PROVIDER_URL is not set.');
}

const encryptorPrivateKey = process.env.ENCRYPTOR_PRIVATE_KEY;
if (!encryptorPrivateKey) {
  throw new Error('ENCRYPTOR_PRIVATE_KEY is not set.');
}

const consumerPrivateKey = process.env.CONSUMER_PRIVATE_KEY;
if (!consumerPrivateKey) {
  throw new Error('CONSUMER_PRIVATE_KEY is not set.');
}

const domain = process.env.DOMAIN || domains.TESTNET;
const ritualId = parseInt(process.env.RITUAL_ID || '6');
const provider = new ethers.providers.JsonRpcProvider(rpcProviderUrl);
const CHAIN_ID_FOR_DOMAIN = {
  [domains.MAINNET]: 137,
  [domains.TESTNET]: 80002,
  [domains.DEVNET]: 80002,
};
const chainId = CHAIN_ID_FOR_DOMAIN[domain];

console.log('Domain:', domain);
console.log('Ritual ID:', ritualId);
console.log('Chain ID:', chainId);

const encryptToBytes = async (messageString: string) => {
  const encryptorSigner = new ethers.Wallet(encryptorPrivateKey);
  console.log(
    "Encryptor signer's address:",
    await encryptorSigner.getAddress(),
  );

  const message = toBytes(messageString);
  console.log(format('Encrypting message ("%s") ...', messageString));

  let universalProfileAddress = ethers.utils.getAddress('0x99Bd76EF9496848ed82F277e1E56079C4Ba3d2cc');

  // function getData(bytes32 dataKey) external view returns (bytes memory);
  const getDataAbi: conditions.base.contract.FunctionAbiProps =  {
    name: 'getData',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      {
        internalType: 'bytes32',
        name: 'dataKey',
        type: 'bytes32',
      },
    ],
    outputs: [
      {
        internalType: 'bytes',
        name: 'dataValue',
        type: 'bytes',
      },
    ],
  };

  /*
  const luksoTokenBalance = new conditions.base.contract.ContractCondition({
    method: 'balanceOf',
    parameters: [ethers.utils.getAddress('0x99bd76ef9496848ed82f277e1e56079c4ba3d2cc')], //':userAddress'],
    standardContractType: 'ERC20',
    contractAddress: ethers.utils.getAddress('0x139aff5e882a747c165fa9e383b13662ddb0e9cd'),
    chain: 42,
    returnValueTest: {
      comparator: '>',
      value: 0,
    },
  });
  */

   // TODO: Currently fixed to controller #2. In practice, the consumer app would generate a proper data key by
   // iterating over all controllers and finding the right one.
   // See https://docs.lukso.tech/standards/access-control/lsp6-key-manager/#retrieving-list-of-controllers
  let controllerDataKey = '0xdf30dba06db6a30e65354d9a64c6098600000000000000000000000000000002';

  const consumerIsController = new conditions.base.contract.ContractCondition({
    method: 'getData',
    functionAbi: getDataAbi,
    parameters: [controllerDataKey],
    contractAddress: universalProfileAddress,
    chain: 42,
    returnValueTest: {
      comparator: '==',
      value: ':userAddress',
    },
  });

  let eoaPermissionsDataKey = '0x4b80742de2bf82acb3630000B0B3F5bf904aA4AeB770929BCFfC323439395878';
  let DECRYPT_PERMISSION = '0x0000000000000000000000000000000000000000000000000000000000100000';

  const consumerHasDecryptPermission = new conditions.base.contract.ContractCondition({
    method: 'getData',
    functionAbi: getDataAbi,
    parameters: [eoaPermissionsDataKey],
    contractAddress: universalProfileAddress,
    chain: 42,
    returnValueTest: {
      comparator: '==',
      value: DECRYPT_PERMISSION,
    },
  });

  const consumerDecryptionCondition = new conditions.compound.CompoundCondition({
    operator: 'and',
    operands: [
      consumerIsController.toObj(),
      consumerHasDecryptPermission.toObj(),
    ],
  });

  const messageKit = await encrypt(
    provider,
    domain,
    message,
    consumerDecryptionCondition,
    ritualId,
    encryptorSigner,
  );

  return messageKit.toBytes();
};

const decryptFromBytes = async (encryptedBytes: Uint8Array) => {
  const consumerSigner = new ethers.Wallet(consumerPrivateKey);
  console.log(
    "\nConsumer signer's address:",
    await consumerSigner.getAddress(),
  );

  const messageKit = ThresholdMessageKit.fromBytes(encryptedBytes);
  console.log('Decrypting message ...');
  const siweParams = {
    domain: 'localhost',
    uri: 'http://localhost:3000',
  };
  const conditionContext =
    conditions.context.ConditionContext.fromMessageKit(messageKit);

  // illustrative optional example of checking what context parameters are required
  // unnecessary if you already know what the condition contains
  if (
    conditionContext.requestedContextParameters.has(USER_ADDRESS_PARAM_DEFAULT)
  ) {
    const authProvider = new EIP4361AuthProvider(
      provider,
      consumerSigner,
      siweParams,
    );
    conditionContext.addAuthProvider(USER_ADDRESS_PARAM_DEFAULT, authProvider);
  }
  return decrypt(provider, domain, messageKit, conditionContext);
};

const runExample = async () => {
  // Make sure the provider is connected to the correct network
  const network = await provider.getNetwork();
  if (network.chainId !== chainId) {
    throw `Please connect your provider to an appropriate network ${chainId}`;
  }
  await initialize();

  const messageString = 'This is a secret 🤐';
  const encryptedBytes = await encryptToBytes(messageString);
  console.log('Ciphertext: ', toHexString(encryptedBytes));

  const decryptedBytes = await decryptFromBytes(encryptedBytes);
  const decryptedMessageString = fromBytes(decryptedBytes);
  console.log('Decrypted message:', decryptedMessageString);

  console.assert(
    decryptedMessageString === messageString,
    'Decrypted message is different to original message',
  );
};

runExample().then(() => {
  console.log('Example finished');
});
