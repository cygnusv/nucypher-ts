import Joi from 'joi';

class Operator {
  static operators: Array<string> = ['and', 'or'];

  constructor(public operator: string) {
    if (!Operator.operators.includes(operator)) {
      throw `"${operator}" is not a valid operator`;
    }
    this.operator = operator;
  }

  toObj() {
    return { operator: this.operator };
  }
}

class ConditionSet {
  constructor(public conditions: Array<Condition | Operator>) {}

  validate() {
    if (this.conditions.length % 2 === 0) {
      throw 'conditions must be odd length, ever other element being an operator';
    }
    this.conditions.forEach((cnd: Condition | Operator, index) => {
      if (index % 2 && cnd.constructor.name !== 'Operator')
        throw `${index} element must be an Operator; Got ${cnd.constructor.name}.`;
      if (!(index % 2) && cnd.constructor.name === 'Operator')
        throw `${index} element must be a Condition; Got ${cnd.constructor.name}.`;
    });
    return true;
  }

  toList() {
    return this.conditions.map((cnd) => {
      return cnd.toObj();
    });
  }

  toJSON() {
    return JSON.stringify(this.toList());
  }

  toBytes() {
    return Buffer.from(this.toJSON()).toString('base64');
  }
}

class Condition {
  defaults = {};
  state = {};

  error: any = {};
  value: any = {};

  toObj() {
    return this.validate().value;
  }

  schema = Joi.object({});

  validate(data: Record<string, unknown> = {}) {
    this.state = Object.assign(this.defaults, this.state, data);
    const { error, value } = this.schema.validate(this.state);
    this.error = error;
    this.value = value;
    return { error, value };
  }

  constructor(data: Record<string, unknown> = {}) {
    this.validate(data);
  }
}

class RPCcondition extends Condition {
  schema = Joi.object({
    chain: Joi.string().required(),

    method: Joi.string().valid('balanceOf', 'eth_getBalance').required(),

    parameters: Joi.array(),

    returnValueTest: Joi.object({
      comparator: Joi.string().valid('==', '>', '<', '<=', '>=').required(),
      value: Joi.string(),
    }),
  });
}

class ContractCondition extends Condition {
  schema = Joi.object({
    contractAddress: Joi.string()
      .pattern(new RegExp('^0x[a-fA-F0-9]{40}$'))
      .required(),

    chain: Joi.string().required(),

    standardContractType: Joi.string(),

    functionAbi: Joi.string(),

    method: Joi.string().required(),

    parameters: Joi.array(),

    returnValueTest: Joi.object({
      comparator: Joi.string().valid('==', '>', '<', '<=', '>=').required(),
      value: Joi.string(),
    }),
  });
}

class ERC721Ownership extends ContractCondition {
  defaults = {
    chain: 'ethereum',
    method: 'ownerOf',
    parameters: [],
    standardContractType: 'ERC721',
    returnValueTest: {
      comparator: '==',
      value: ':userAddress',
    },
  };
}

const Conditions = {
  ERC721Ownership,
};

export { Operator, ConditionSet, Conditions };