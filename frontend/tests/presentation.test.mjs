import test from 'node:test'
import assert from 'node:assert/strict'
import { filterByCategory, normalizeFindingStatus, resourcePhase } from '../src/presentation.ts'

test('finding statuses preserve ERROR, UNKNOWN, BLOCKED and INDETERMINATE distinctions', () => {
  assert.equal(normalizeFindingStatus('ERROR'), 'Error')
  assert.equal(normalizeFindingStatus('UNKNOWN'), 'Unknown')
  assert.equal(normalizeFindingStatus('BLOCKED'), 'Blocked')
  assert.equal(normalizeFindingStatus('INDETERMINATE'), 'Indeterminate')
  assert.equal(normalizeFindingStatus('PASS'), 'Pass')
  assert.equal(normalizeFindingStatus('FAIL'), 'Fail')
})

test('API resource states distinguish loading, authorization, error, empty and success', () => {
  assert.equal(resourcePhase({ loading: true, error: '', auth: false, hasValue: false }), 'loading')
  assert.equal(resourcePhase({ loading: false, error: '', auth: true, hasValue: false }), 'auth-required')
  assert.equal(resourcePhase({ loading: false, error: 'unavailable', auth: false, hasValue: false }), 'error')
  assert.equal(resourcePhase({ loading: false, error: '', auth: false, hasValue: true, empty: true }), 'empty')
  assert.equal(resourcePhase({ loading: false, error: '', auth: false, hasValue: true }), 'available')
  assert.equal(resourcePhase({ loading: false, error: '', auth: false, hasValue: false }), 'not-run')
})

test('simulated event filtering is deterministic and supports an empty result', () => {
  const events = [{ category: 'connection_attempt' }, { category: 'auth_probe' }]
  assert.deepEqual(filterByCategory(events, 'connection_attempt'), [events[0]])
  assert.deepEqual(filterByCategory(events, 'All categories'), events)
  assert.deepEqual(filterByCategory(events, 'missing'), [])
})
