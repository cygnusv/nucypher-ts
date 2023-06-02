import { EvmCondition } from '../../../../src/conditions/base';
import { testEvmConditionObj } from '../../testVariables';

describe('validation', () => {
  it('accepts on a valid schema', () => {
    const evm = new EvmCondition(testEvmConditionObj);
    expect(evm.toObj()).toEqual(testEvmConditionObj);
  });

  it('rejects an invalid schema', () => {
    const badEvmCondition = {
      ...testEvmConditionObj,
      // Intentionally removing `contractAddress`
      contractAddress: undefined,
    };
    const badEvm = new EvmCondition(badEvmCondition);
    expect(() => badEvm.toObj()).toThrow(
      'Invalid condition: "contractAddress" is required'
    );

    const { error } = badEvm.validate(badEvmCondition);
    expect(error?.message).toEqual('"contractAddress" is required');
  });
});

describe('accepts either standardContractType or functionAbi but not both or none', () => {
  const standardContractType = 'ERC20';
  const functionAbi = { fake_function_abi: true };

  it('accepts standardContractType', () => {
    const conditionObj = {
      ...testEvmConditionObj,
      standardContractType,
      functionAbi: undefined,
    };
    const evmCondition = new EvmCondition(conditionObj);
    expect(evmCondition.toObj()).toEqual(conditionObj);
  });

  it('accepts functionAbi', () => {
    const conditionObj = {
      ...testEvmConditionObj,
      functionAbi,
      standardContractType: undefined,
    };
    const evmCondition = new EvmCondition(conditionObj);
    expect(evmCondition.toObj()).toEqual(conditionObj);
  });

  it('rejects both', () => {
    const conditionObj = {
      ...testEvmConditionObj,
      standardContractType,
      functionAbi,
    };
    const evmCondition = new EvmCondition(conditionObj);
    expect(() => evmCondition.toObj()).toThrow(
      '"value" contains a conflict between exclusive peers [standardContractType, functionAbi]'
    );
  });

  it('rejects none', () => {
    const conditionObj = {
      ...testEvmConditionObj,
      standardContractType: undefined,
      functionAbi: undefined,
    };
    const evmCondition = new EvmCondition(conditionObj);
    expect(() => evmCondition.toObj()).toThrow(
      '"value" must contain at least one of [standardContractType, functionAbi]'
    );
  });
});

// TODO(#124)
// it('accepts custom parameters in function abi methods', async () => {
//     throw new Error('Not implemented');
// });

// TODO(#124)
// describe('supports custom function abi', () => {
//   const fakeFunctionAbi = {
//     name: 'myFunction',
//     type: 'function',
//     inputs: [
//       {
//         name: 'account',
//         type: 'address',
//       },
//       {
//         name: 'myCustomParam',
//         type: 'uint256',
//       },
//     ],
//     outputs: [
//       {
//         name: 'someValue',
//         type: 'uint256',
//       },
//     ],
//   };
//   const evmConditionObj = {
//     ...testEvmConditionObj,
//     functionAbi: fakeFunctionAbi,
//     method: 'myFunction',
//     parameters: [USER_ADDRESS_PARAM, ':customParam'],
//     returnValueTest: {
//       index: 0,
//       comparator: '==',
//       value: USER_ADDRESS_PARAM,
//     },
//   };
//   const evmCondition = new EvmCondition(evmConditionObj);
//   const web3Provider = fakeWeb3Provider(SecretKey.random().toBEBytes());
//   const conditionSet = new ConditionSet([evmCondition]);
//   const conditionContext = new ConditionContext(
//     conditionSet.toWASMConditions(),
//     web3Provider
//   );
//   const myCustomParam = ':customParam';
//   const customParams: Record<string, CustomContextParam> = {};
//   customParams[myCustomParam] = 1234;
//
//   it('accepts custom function abi', async () => {
//     const asJson = await conditionContext
//       .withCustomParams(customParams)
//       .toJson();
//     expect(asJson).toBeDefined();
//     expect(asJson).toContain(USER_ADDRESS_PARAM);
//     expect(asJson).toContain(myCustomParam);
//   });
// });
