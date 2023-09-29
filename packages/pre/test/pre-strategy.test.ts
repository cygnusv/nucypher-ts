import { SecretKey, VerifiedKeyFrag } from '@nucypher/nucypher-core';
import { Ursula } from '@nucypher/shared';
import {
  aliceSecretKeyBytes,
  bobSecretKeyBytes,
  fakeProvider,
  fakeSigner,
  fakeUrsulas,
  makeCohort,
  mockGetUrsulas,
  mockRetrieveCFragsRequest,
} from '@nucypher/test-utils';
import { afterEach, expect, test, vi } from 'vitest';

import {
  conditions,
  DeployedPreStrategy,
  PreDecrypter,
  PreStrategy,
  toBytes,
} from '../src';

import {
  mockEncryptTreasureMap,
  mockGenerateKFrags,
  mockMakeTreasureMap,
  mockPublishToBlockchain,
} from './test-utils';

// Shared test variables
const ownsNFT = new conditions.ERC721Ownership({
  contractAddress: '0x1e988ba4692e52Bc50b375bcC8585b95c48AaD77',
  parameters: [3591],
  chain: 5,
});
const conditionExpr = new conditions.ConditionExpression(ownsNFT);

const makePreStrategy = async () => {
  const aliceSecretKey = SecretKey.fromBEBytes(aliceSecretKeyBytes);
  const bobSecretKey = SecretKey.fromBEBytes(bobSecretKeyBytes);
  const cohort = await makeCohort(fakeUrsulas());
  const strategy = PreStrategy.create(cohort, aliceSecretKey, bobSecretKey);
  expect(strategy.cohort).toEqual(cohort);
  return strategy;
};

const makeDeployedPreStrategy = async () => {
  const aliceSecretKey = SecretKey.fromBEBytes(aliceSecretKeyBytes);
  const aliceSigner = fakeSigner(aliceSecretKey.toBEBytes());
  const aliceProvider = fakeProvider(aliceSecretKey.toBEBytes());

  const strategy = await makePreStrategy();
  const generateKFragsSpy = mockGenerateKFrags();
  const publishToBlockchainSpy = mockPublishToBlockchain();
  const makeTreasureMapSpy = mockMakeTreasureMap();
  const encryptTreasureMapSpy = mockEncryptTreasureMap();

  const deployedStrategy = await strategy.deploy(
    aliceProvider,
    aliceSigner,
    'test',
  );

  expect(generateKFragsSpy).toHaveBeenCalled();
  expect(publishToBlockchainSpy).toHaveBeenCalled();
  expect(makeTreasureMapSpy).toHaveBeenCalled();
  expect(encryptTreasureMapSpy).toHaveBeenCalled();

  expect(deployedStrategy.cohort).toEqual(strategy.cohort);

  const ursulaAddresses = (
    makeTreasureMapSpy.mock.calls[0][0] as readonly Ursula[]
  ).map((u) => u.checksumAddress);
  const verifiedKFrags = makeTreasureMapSpy.mock
    .calls[0][1] as readonly VerifiedKeyFrag[];

  return { deployedStrategy, ursulaAddresses, verifiedKFrags };
};

test('pre strategy', () => {
  test('PreStrategy', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    test('creates a strategy', async () => {
      await makePreStrategy();
    });

    test('deploys a strategy', async () => {
      await makeDeployedPreStrategy();
    });

    test('serialization', () => {
      test('serializes to plain object', async () => {
        const strategy = await makePreStrategy();
        const asObject = strategy.toObj();
        const fromObject = PreStrategy.fromObj(asObject);
        expect(fromObject.equals(strategy)).toBeTruthy();
      });

      test('serializes to JSON', async () => {
        const strategy = await makePreStrategy();
        const asJson = strategy.toJSON();
        const fromJSON = PreStrategy.fromJSON(asJson);
        expect(fromJSON.equals(strategy)).toBeTruthy();
      });
    });
  });

  test('PreDeployedStrategy', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    test('encrypts and decrypts', async () => {
      const bobSecretKey = SecretKey.fromBEBytes(bobSecretKeyBytes);
      const bobSigner = fakeSigner(bobSecretKey.toBEBytes());
      const bobProvider = fakeProvider(bobSecretKey.toBEBytes());
      const { deployedStrategy, ursulaAddresses, verifiedKFrags } =
        await makeDeployedPreStrategy();

      const plaintext = 'this is a secret';
      const encryptedMessageKit = deployedStrategy
        .makeEncrypter(conditionExpr)
        .encryptMessagePre(plaintext);

      // Setup mocks for `retrieveAndDecrypt`
      const getUrsulasSpy = mockGetUrsulas();
      const retrieveCFragsSpy = mockRetrieveCFragsRequest(
        ursulaAddresses,
        verifiedKFrags,
        encryptedMessageKit.capsule,
      );

      const decryptedMessage =
        await deployedStrategy.decrypter.retrieveAndDecrypt(
          bobProvider,
          bobSigner,
          [encryptedMessageKit],
        );
      expect(getUrsulasSpy).toHaveBeenCalled();
      expect(retrieveCFragsSpy).toHaveBeenCalled();
      expect(decryptedMessage[0]).toEqual(toBytes(plaintext));
    });

    test('serialization', () => {
      test('serializes to a plain object', async () => {
        const { deployedStrategy } = await makeDeployedPreStrategy();
        const asObj = deployedStrategy.toObj();
        const fromJson = DeployedPreStrategy.fromObj(asObj);
        expect(fromJson.equals(deployedStrategy)).toBeTruthy();
      });

      test('serializes to a JSON', async () => {
        const { deployedStrategy } = await makeDeployedPreStrategy();
        const asJson = deployedStrategy.toJSON();
        const fromJson = DeployedPreStrategy.fromJSON(asJson);
        expect(fromJson.equals(deployedStrategy)).toBeTruthy();
      });
    });
  });

  test('PreDecrypter', () => {
    test('serializes to a plain object', async () => {
      const { deployedStrategy } = await makeDeployedPreStrategy();
      const asObj = deployedStrategy.decrypter.toObj();
      const fromJson = PreDecrypter.fromObj(asObj);
      expect(fromJson.equals(deployedStrategy.decrypter)).toBeTruthy();
    });

    test('serializes to JSON', async () => {
      const { deployedStrategy } = await makeDeployedPreStrategy();
      const asJson = deployedStrategy.decrypter.toJSON();
      const fromJson = PreDecrypter.fromJSON(asJson);
      expect(fromJson.equals(deployedStrategy.decrypter)).toBeTruthy();
    });
  });
});