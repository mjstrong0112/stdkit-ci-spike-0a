import assert from 'node:assert/strict';
import { test } from 'node:test';

import { greeting } from '../src/message-s10.ts';

test('greeting addresses the supplied name', () => {
  assert.equal(greeting('sandbox'), 'Hello, sandbox.');
});
