import { DkgPublicKey } from '@nucypher/nucypher-core';
import { PublicClient, WalletClient } from 'viem';

import { DkgCoordinatorAgent, DkgRitualState } from './agents/coordinator';
import { ChecksumAddress } from './types';
import { fromHexString, objectEquals } from './utils';
import { toPublicClient } from './viem';

export type DkgRitualParameters = {
  sharesNum: number;
  threshold: number;
};

export interface DkgRitualJSON {
  id: number;
  dkgPublicKey: Uint8Array;
  dkgParams: DkgRitualParameters;
  state: DkgRitualState;
}

export class DkgRitual {
  constructor(
    public readonly id: number,
    public readonly dkgPublicKey: DkgPublicKey,
    public readonly dkgParams: DkgRitualParameters,
    public readonly state: DkgRitualState
  ) {}

  public toObj(): DkgRitualJSON {
    return {
      id: this.id,
      dkgPublicKey: this.dkgPublicKey.toBytes(),
      dkgParams: this.dkgParams,
      state: this.state,
    };
  }

  public static fromObj({
    id,
    dkgPublicKey,
    dkgParams,
    state,
  }: DkgRitualJSON): DkgRitual {
    return new DkgRitual(
      id,
      DkgPublicKey.fromBytes(dkgPublicKey),
      dkgParams,
      state
    );
  }

  public equals(other: DkgRitual): boolean {
    return [
      this.id === other.id,
      this.dkgPublicKey.equals(other.dkgPublicKey),
      objectEquals(this.dkgParams, other.dkgParams),
      this.state === other.state,
    ].every(Boolean);
  }
}

// TODO: Currently, we're assuming that the threshold is always `floor(sharesNum / 2) + 1`.
//  https://github.com/nucypher/nucypher/issues/3095
const assumedThreshold = (sharesNum: number): number =>
  Math.floor(sharesNum / 2) + 1;

export class DkgClient {
  public static async initializeRitual(
    walletClient: WalletClient,
    ursulas: ChecksumAddress[],
    waitUntilEnd = false
  ): Promise<number | undefined> {
    const publicClient = toPublicClient(walletClient);
    const ritualId = await DkgCoordinatorAgent.initializeRitual(
      walletClient,
      ursulas.sort()
    );

    if (waitUntilEnd) {
      const isSuccessful = await DkgClient.waitUntilRitualEnd(
        publicClient,
        ritualId
      );
      if (!isSuccessful) {
        const ritualState = await DkgCoordinatorAgent.getRitualState(
          publicClient,
          ritualId
        );
        throw new Error(
          `Ritual initialization failed. Ritual id ${ritualId} is in state ${ritualState}`
        );
      }
    }

    return ritualId;
  }

  private static waitUntilRitualEnd = async (
    publicClient: PublicClient,
    ritualId: number
  ): Promise<boolean> => {
    return new Promise((resolve, reject) => {
      const callback = (successful: boolean) => {
        if (successful) {
          resolve(true);
        } else {
          reject();
        }
      };
      DkgCoordinatorAgent.onRitualEndEvent(publicClient, ritualId, callback);
    });
  };

  public static async getExistingRitual(
    publicClient: PublicClient,
    ritualId: number
  ): Promise<DkgRitual> {
    const ritualState = await DkgCoordinatorAgent.getRitualState(
      publicClient,
      ritualId
    );
    const ritual = await DkgCoordinatorAgent.getRitual(publicClient, ritualId);
    const dkgPkBytes = new Uint8Array([
      ...fromHexString(ritual.publicKey.word0),
      ...fromHexString(ritual.publicKey.word1),
    ]);
    return new DkgRitual(
      ritualId,
      DkgPublicKey.fromBytes(dkgPkBytes),
      {
        sharesNum: ritual.dkgSize,
        threshold: assumedThreshold(ritual.dkgSize),
      },
      ritualState
    );
  }

  // TODO: Without Validator public key in Coordinator, we cannot verify the
  //    transcript. We need to add it to the Coordinator (nucypher-contracts #77).
  // public async verifyRitual(ritualId: number): Promise<boolean> {
  //   const ritual = await DkgCoordinatorAgent.getRitual(this.provider, ritualId);
  //   const participants = await DkgCoordinatorAgent.getParticipants(
  //     this.provider,
  //     ritualId
  //   );
  //
  //   const validatorMessages = participants.map((p) => {
  //     const validatorAddress = EthereumAddress.fromString(p.provider);
  //     const publicKey = FerveoPublicKey.fromBytes(fromHexString(p.???));
  //     const validator = new Validator(validatorAddress, publicKey);
  //     const transcript = Transcript.fromBytes(fromHexString(p.transcript));
  //     return new ValidatorMessage(validator, transcript);
  //   });
  //   const aggregate = new AggregatedTranscript(validatorMessages);
  //
  //   return aggregate.verify(ritual.dkgSize, validatorMessages);
  // }
}
