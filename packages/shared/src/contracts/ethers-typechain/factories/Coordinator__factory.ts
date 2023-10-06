/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Signer, utils } from "ethers";
import type { Provider } from "@ethersproject/providers";
import type { Coordinator, CoordinatorInterface } from "../Coordinator";

const _abi = [
  {
    type: "constructor",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "_application",
        type: "address",
        internalType: "contract ITACoChildApplication",
      },
      {
        name: "_timeout",
        type: "uint32",
        internalType: "uint32",
      },
      {
        name: "_maxDkgSize",
        type: "uint16",
        internalType: "uint16",
      },
      {
        name: "_admin",
        type: "address",
        internalType: "address",
      },
      {
        name: "_currency",
        type: "address",
        internalType: "contract IERC20",
      },
      {
        name: "_feeRatePerSecond",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "event",
    name: "AggregationPosted",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
        indexed: true,
      },
      {
        name: "node",
        type: "address",
        internalType: "address",
        indexed: true,
      },
      {
        name: "aggregatedTranscriptDigest",
        type: "bytes32",
        internalType: "bytes32",
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "DefaultAdminDelayChangeCanceled",
    inputs: [],
    anonymous: false,
  },
  {
    type: "event",
    name: "DefaultAdminDelayChangeScheduled",
    inputs: [
      {
        name: "newDelay",
        type: "uint48",
        internalType: "uint48",
        indexed: false,
      },
      {
        name: "effectSchedule",
        type: "uint48",
        internalType: "uint48",
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "DefaultAdminTransferCanceled",
    inputs: [],
    anonymous: false,
  },
  {
    type: "event",
    name: "DefaultAdminTransferScheduled",
    inputs: [
      {
        name: "newAdmin",
        type: "address",
        internalType: "address",
        indexed: true,
      },
      {
        name: "acceptSchedule",
        type: "uint48",
        internalType: "uint48",
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "EndRitual",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
        indexed: true,
      },
      {
        name: "successful",
        type: "bool",
        internalType: "bool",
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "MaxDkgSizeChanged",
    inputs: [
      {
        name: "oldSize",
        type: "uint16",
        internalType: "uint16",
        indexed: false,
      },
      {
        name: "newSize",
        type: "uint16",
        internalType: "uint16",
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "ParticipantPublicKeySet",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
        indexed: true,
      },
      {
        name: "participant",
        type: "address",
        internalType: "address",
        indexed: true,
      },
      {
        name: "publicKey",
        type: "tuple",
        components: [
          {
            name: "word0",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "word1",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "word2",
            type: "bytes32",
            internalType: "bytes32",
          },
        ],
        internalType: "struct BLS12381.G2Point",
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "RoleAdminChanged",
    inputs: [
      {
        name: "role",
        type: "bytes32",
        internalType: "bytes32",
        indexed: true,
      },
      {
        name: "previousAdminRole",
        type: "bytes32",
        internalType: "bytes32",
        indexed: true,
      },
      {
        name: "newAdminRole",
        type: "bytes32",
        internalType: "bytes32",
        indexed: true,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "RoleGranted",
    inputs: [
      {
        name: "role",
        type: "bytes32",
        internalType: "bytes32",
        indexed: true,
      },
      {
        name: "account",
        type: "address",
        internalType: "address",
        indexed: true,
      },
      {
        name: "sender",
        type: "address",
        internalType: "address",
        indexed: true,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "RoleRevoked",
    inputs: [
      {
        name: "role",
        type: "bytes32",
        internalType: "bytes32",
        indexed: true,
      },
      {
        name: "account",
        type: "address",
        internalType: "address",
        indexed: true,
      },
      {
        name: "sender",
        type: "address",
        internalType: "address",
        indexed: true,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "StartAggregationRound",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
        indexed: true,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "StartRitual",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
        indexed: true,
      },
      {
        name: "authority",
        type: "address",
        internalType: "address",
        indexed: true,
      },
      {
        name: "participants",
        type: "address[]",
        internalType: "address[]",
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "TimeoutChanged",
    inputs: [
      {
        name: "oldTimeout",
        type: "uint32",
        internalType: "uint32",
        indexed: false,
      },
      {
        name: "newTimeout",
        type: "uint32",
        internalType: "uint32",
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "TranscriptPosted",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
        indexed: true,
      },
      {
        name: "node",
        type: "address",
        internalType: "address",
        indexed: true,
      },
      {
        name: "transcriptDigest",
        type: "bytes32",
        internalType: "bytes32",
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: "function",
    name: "DEFAULT_ADMIN_ROLE",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
  },
  {
    type: "function",
    name: "INITIATOR_ROLE",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
  },
  {
    type: "function",
    name: "TREASURY_ROLE",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
  },
  {
    type: "function",
    name: "acceptDefaultAdminTransfer",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    type: "function",
    name: "application",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "contract ITACoChildApplication",
      },
    ],
  },
  {
    type: "function",
    name: "beginDefaultAdminTransfer",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "newAdmin",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "cancelDefaultAdminTransfer",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    type: "function",
    name: "changeDefaultAdminDelay",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "newDelay",
        type: "uint48",
        internalType: "uint48",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "cohortFingerprint",
    stateMutability: "pure",
    inputs: [
      {
        name: "nodes",
        type: "address[]",
        internalType: "address[]",
      },
    ],
    outputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
  },
  {
    type: "function",
    name: "currency",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "contract IERC20",
      },
    ],
  },
  {
    type: "function",
    name: "defaultAdmin",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "address",
      },
    ],
  },
  {
    type: "function",
    name: "defaultAdminDelay",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint48",
        internalType: "uint48",
      },
    ],
  },
  {
    type: "function",
    name: "defaultAdminDelayIncreaseWait",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint48",
        internalType: "uint48",
      },
    ],
  },
  {
    type: "function",
    name: "feeRatePerSecond",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "function",
    name: "getAuthority",
    stateMutability: "view",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
    ],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "address",
      },
    ],
  },
  {
    type: "function",
    name: "getParticipantFromProvider",
    stateMutability: "view",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
      {
        name: "provider",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          {
            name: "provider",
            type: "address",
            internalType: "address",
          },
          {
            name: "aggregated",
            type: "bool",
            internalType: "bool",
          },
          {
            name: "transcript",
            type: "bytes",
            internalType: "bytes",
          },
          {
            name: "decryptionRequestStaticKey",
            type: "bytes",
            internalType: "bytes",
          },
        ],
        internalType: "struct Coordinator.Participant",
      },
    ],
  },
  {
    type: "function",
    name: "getParticipants",
    stateMutability: "view",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
    ],
    outputs: [
      {
        name: "",
        type: "tuple[]",
        components: [
          {
            name: "provider",
            type: "address",
            internalType: "address",
          },
          {
            name: "aggregated",
            type: "bool",
            internalType: "bool",
          },
          {
            name: "transcript",
            type: "bytes",
            internalType: "bytes",
          },
          {
            name: "decryptionRequestStaticKey",
            type: "bytes",
            internalType: "bytes",
          },
        ],
        internalType: "struct Coordinator.Participant[]",
      },
    ],
  },
  {
    type: "function",
    name: "getProviderPublicKey",
    stateMutability: "view",
    inputs: [
      {
        name: "_provider",
        type: "address",
        internalType: "address",
      },
      {
        name: "_ritualId",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          {
            name: "word0",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "word1",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "word2",
            type: "bytes32",
            internalType: "bytes32",
          },
        ],
        internalType: "struct BLS12381.G2Point",
      },
    ],
  },
  {
    type: "function",
    name: "getPublicKeyFromRitualId",
    stateMutability: "view",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
    ],
    outputs: [
      {
        name: "dkgPublicKey",
        type: "tuple",
        components: [
          {
            name: "word0",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "word1",
            type: "bytes16",
            internalType: "bytes16",
          },
        ],
        internalType: "struct BLS12381.G1Point",
      },
    ],
  },
  {
    type: "function",
    name: "getRitualIdFromPublicKey",
    stateMutability: "view",
    inputs: [
      {
        name: "dkgPublicKey",
        type: "tuple",
        components: [
          {
            name: "word0",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "word1",
            type: "bytes16",
            internalType: "bytes16",
          },
        ],
        internalType: "struct BLS12381.G1Point",
      },
    ],
    outputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
    ],
  },
  {
    type: "function",
    name: "getRitualInitiationCost",
    stateMutability: "view",
    inputs: [
      {
        name: "providers",
        type: "address[]",
        internalType: "address[]",
      },
      {
        name: "duration",
        type: "uint32",
        internalType: "uint32",
      },
    ],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "function",
    name: "getRitualState",
    stateMutability: "view",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
    ],
    outputs: [
      {
        name: "",
        type: "uint8",
        internalType: "enum Coordinator.RitualState",
      },
    ],
  },
  {
    type: "function",
    name: "getRoleAdmin",
    stateMutability: "view",
    inputs: [
      {
        name: "role",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
  },
  {
    type: "function",
    name: "getThresholdForRitualSize",
    stateMutability: "pure",
    inputs: [
      {
        name: "size",
        type: "uint16",
        internalType: "uint16",
      },
    ],
    outputs: [
      {
        name: "",
        type: "uint16",
        internalType: "uint16",
      },
    ],
  },
  {
    type: "function",
    name: "grantRole",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "role",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "account",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "hasRole",
    stateMutability: "view",
    inputs: [
      {
        name: "role",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "account",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [
      {
        name: "",
        type: "bool",
        internalType: "bool",
      },
    ],
  },
  {
    type: "function",
    name: "initiateRitual",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "providers",
        type: "address[]",
        internalType: "address[]",
      },
      {
        name: "authority",
        type: "address",
        internalType: "address",
      },
      {
        name: "duration",
        type: "uint32",
        internalType: "uint32",
      },
      {
        name: "accessController",
        type: "address",
        internalType: "contract IEncryptionAuthorizer",
      },
    ],
    outputs: [
      {
        name: "",
        type: "uint32",
        internalType: "uint32",
      },
    ],
  },
  {
    type: "function",
    name: "isEncryptionAuthorized",
    stateMutability: "view",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
      {
        name: "evidence",
        type: "bytes",
        internalType: "bytes",
      },
      {
        name: "ciphertextHeader",
        type: "bytes",
        internalType: "bytes",
      },
    ],
    outputs: [
      {
        name: "",
        type: "bool",
        internalType: "bool",
      },
    ],
  },
  {
    type: "function",
    name: "isInitiationPublic",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "bool",
        internalType: "bool",
      },
    ],
  },
  {
    type: "function",
    name: "isProviderPublicKeySet",
    stateMutability: "view",
    inputs: [
      {
        name: "_provider",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [
      {
        name: "",
        type: "bool",
        internalType: "bool",
      },
    ],
  },
  {
    type: "function",
    name: "isRitualFinalized",
    stateMutability: "view",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
    ],
    outputs: [
      {
        name: "",
        type: "bool",
        internalType: "bool",
      },
    ],
  },
  {
    type: "function",
    name: "makeInitiationPublic",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    type: "function",
    name: "maxDkgSize",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint16",
        internalType: "uint16",
      },
    ],
  },
  {
    type: "function",
    name: "numberOfRituals",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "function",
    name: "owner",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "address",
      },
    ],
  },
  {
    type: "function",
    name: "pendingDefaultAdmin",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "newAdmin",
        type: "address",
        internalType: "address",
      },
      {
        name: "schedule",
        type: "uint48",
        internalType: "uint48",
      },
    ],
  },
  {
    type: "function",
    name: "pendingDefaultAdminDelay",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "newDelay",
        type: "uint48",
        internalType: "uint48",
      },
      {
        name: "schedule",
        type: "uint48",
        internalType: "uint48",
      },
    ],
  },
  {
    type: "function",
    name: "pendingFees",
    stateMutability: "view",
    inputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "function",
    name: "postAggregation",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
      {
        name: "aggregatedTranscript",
        type: "bytes",
        internalType: "bytes",
      },
      {
        name: "dkgPublicKey",
        type: "tuple",
        components: [
          {
            name: "word0",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "word1",
            type: "bytes16",
            internalType: "bytes16",
          },
        ],
        internalType: "struct BLS12381.G1Point",
      },
      {
        name: "decryptionRequestStaticKey",
        type: "bytes",
        internalType: "bytes",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "postTranscript",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
      {
        name: "transcript",
        type: "bytes",
        internalType: "bytes",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "processPendingFee",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "renounceRole",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "role",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "account",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "revokeRole",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "role",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "account",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "rituals",
    stateMutability: "view",
    inputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    outputs: [
      {
        name: "initiator",
        type: "address",
        internalType: "address",
      },
      {
        name: "initTimestamp",
        type: "uint32",
        internalType: "uint32",
      },
      {
        name: "endTimestamp",
        type: "uint32",
        internalType: "uint32",
      },
      {
        name: "totalTranscripts",
        type: "uint16",
        internalType: "uint16",
      },
      {
        name: "totalAggregations",
        type: "uint16",
        internalType: "uint16",
      },
      {
        name: "authority",
        type: "address",
        internalType: "address",
      },
      {
        name: "dkgSize",
        type: "uint16",
        internalType: "uint16",
      },
      {
        name: "threshold",
        type: "uint16",
        internalType: "uint16",
      },
      {
        name: "aggregationMismatch",
        type: "bool",
        internalType: "bool",
      },
      {
        name: "accessController",
        type: "address",
        internalType: "contract IEncryptionAuthorizer",
      },
      {
        name: "publicKey",
        type: "tuple",
        components: [
          {
            name: "word0",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "word1",
            type: "bytes16",
            internalType: "bytes16",
          },
        ],
        internalType: "struct BLS12381.G1Point",
      },
      {
        name: "aggregatedTranscript",
        type: "bytes",
        internalType: "bytes",
      },
    ],
  },
  {
    type: "function",
    name: "rollbackDefaultAdminDelay",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    type: "function",
    name: "setMaxDkgSize",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "newSize",
        type: "uint16",
        internalType: "uint16",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "setProviderPublicKey",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "_publicKey",
        type: "tuple",
        components: [
          {
            name: "word0",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "word1",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "word2",
            type: "bytes32",
            internalType: "bytes32",
          },
        ],
        internalType: "struct BLS12381.G2Point",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "setReimbursementPool",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "pool",
        type: "address",
        internalType: "contract IReimbursementPool",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "setRitualAuthority",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "ritualId",
        type: "uint32",
        internalType: "uint32",
      },
      {
        name: "authority",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "setTimeout",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "newTimeout",
        type: "uint32",
        internalType: "uint32",
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "supportsInterface",
    stateMutability: "view",
    inputs: [
      {
        name: "interfaceId",
        type: "bytes4",
        internalType: "bytes4",
      },
    ],
    outputs: [
      {
        name: "",
        type: "bool",
        internalType: "bool",
      },
    ],
  },
  {
    type: "function",
    name: "timeout",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint32",
        internalType: "uint32",
      },
    ],
  },
  {
    type: "function",
    name: "totalPendingFees",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "function",
    name: "withdrawTokens",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "token",
        type: "address",
        internalType: "contract IERC20",
      },
      {
        name: "amount",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    outputs: [],
  },
] as const;

export class Coordinator__factory {
  static readonly abi = _abi;
  static createInterface(): CoordinatorInterface {
    return new utils.Interface(_abi) as CoordinatorInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): Coordinator {
    return new Contract(address, _abi, signerOrProvider) as Coordinator;
  }
}
