import Joi from 'joi';

import { ETH_ADDRESS_REGEXP } from '../const';

import { RpcCondition, rpcConditionSchema } from './rpc';

export const STANDARD_CONTRACT_TYPES = ['ERC20', 'ERC721'];

const functionAbiVariable = Joi.object({
  internalType: Joi.string().required(),
  name: Joi.string().required(),
  type: Joi.string().required(),
});

const functionAbiSchema = Joi.object({
  name: Joi.string().required(),
  type: Joi.string().valid('function').required(),
  inputs: Joi.array().items(functionAbiVariable),
  outputs: Joi.array().items(functionAbiVariable),
  // TODO: Should we restrict this to 'view'?
  // stateMutability: Joi.string().valid('view').required(),
}).custom((functionAbi, helper) => {
  // Validate method name
  const method = helper.state.ancestors[0].method;
  if (functionAbi.name !== method) {
    return helper.message({
      custom: '"method" must be the same as "functionAbi.name"',
    });
  }

  // Validate nr of parameters
  const parameters = helper.state.ancestors[0].parameters;
  if (functionAbi.inputs?.length !== parameters.length) {
    return helper.message({
      custom: '"parameters" must have the same length as "functionAbi.inputs"',
    });
  }

  return functionAbi;
});

const contractMethodSchemas: Record<string, Joi.Schema> = {
  ...rpcConditionSchema,
  contractAddress: Joi.string().pattern(ETH_ADDRESS_REGEXP).required(),
  standardContractType: Joi.string()
    .valid(...STANDARD_CONTRACT_TYPES)
    .optional(),
  method: Joi.string().required(),
  functionAbi: functionAbiSchema.optional(),
  parameters: Joi.array().required(),
};

export class ContractCondition extends RpcCondition {
  public readonly schema = Joi.object(contractMethodSchemas)
    // At most one of these keys needs to be present
    .xor('standardContractType', 'functionAbi');
}