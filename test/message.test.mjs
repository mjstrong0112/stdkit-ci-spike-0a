import assert from 'node:assert/strict';
import { test } from 'node:test';

import { greeting } from '../src/message.ts';

test('greeting addresses the supplied name', () => {
  assert.equal(greeting('sandbox'), 'Hello, sandbox.');
});

test('delayed clean check for S8c out-of-order proof', async () => {
  await new Promise((resolve) => setTimeout(resolve, 90_000));
  assert.equal(greeting('slow'), 'Hello, slow.');
});
