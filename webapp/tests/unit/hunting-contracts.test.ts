import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { validateHuntingBundle, listHunts, getHunt } from '../../lib/hunting-contracts.ts'
const bundle = JSON.parse(readFileSync(new URL('../../../queries/hunting_integration_bundle.json', import.meta.url), 'utf8'))

test('validates shared bundle and rejects tampered query', () => {
  const parsed = validateHuntingBundle(bundle)
  assert.equal(parsed.queries.length, 163)
  const storylinePage = listHunts(parsed, new URLSearchParams('pack=storyline_7day_caldera_goad&limit=20'))
  assert.equal(storylinePage.total, 7)
  const bad = structuredClone(bundle)
  bad.queries[0].query += ' | head 1'
  assert.throws(() => validateHuntingBundle(bad))
})
test('bounded filter parity and encoded identifier retrieval', () => {
  const parsed = validateHuntingBundle(bundle)
  const page = listHunts(parsed, new URLSearchParams('pack=identity_credentials&limit=1'))
  assert.equal(page.total, 3)
  assert.equal(page.items.length, 1)
  assert.equal(getHunt(parsed, page.items[0].id).id, page.items[0].id)
  for (const q of ['limit=201', 'limit=0','offset=-1','unknown=x','readiness=maybe','limit=1.5']) {
    assert.throws(() => listHunts(parsed, new URLSearchParams(q)))
  }
  assert.throws(() => getHunt(parsed,'../../config'))
})
