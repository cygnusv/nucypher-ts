import { z } from 'zod';

import { CONTEXT_PARAM_REGEXP } from '../const';

import { plainStringSchema } from './common';

export const contextParamSchema = z.string().regex(CONTEXT_PARAM_REGEXP);

// TODO: This is too broad, but it's a start
const paramSchema = z.union([plainStringSchema, z.boolean(), z.number().int().nonnegative()]);

export const paramOrContextParamSchema: z.ZodSchema = z.union([
  paramSchema,
  contextParamSchema,
  z.lazy(() => z.array(paramOrContextParamSchema)),
]);
