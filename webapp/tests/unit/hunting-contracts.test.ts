import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { validateHuntingBundle, listHunts, getHunt } from '../../lib/hunting-contracts.ts'
const bundle = JSON.parse(readFileSync(new URL('../../../queries/hunting_integration_bundle.json', import.meta.url), 'utf8'))
const canonicalSourcePaths = readdirSync(new URL('../../../queries/hunting/', import.meta.url), { withFileTypes: true })
  .filter(entry => entry.isFile() && entry.name.endsWith('.json'))
  .map(entry => `hunting/${entry.name}`)
  .sort()

function assertCanonicalSourceMembership(sourcePaths: string[]) {
  assert.equal(new Set(sourcePaths).size, sourcePaths.length, 'source paths must be unique')
  assert.deepEqual([...sourcePaths].sort(), canonicalSourcePaths)
}

test('validates shared bundle and rejects tampered query', () => {
  const parsed = validateHuntingBundle(bundle)
  const sourcePaths = parsed.queries.map(query => query.source_path)
  assertCanonicalSourceMembership(sourcePaths)
  assert.throws(() => assertCanonicalSourceMembership(sourcePaths.slice(1)))
  assert.throws(() => assertCanonicalSourceMembership([...sourcePaths, sourcePaths[0]]))
  const allHunts = listHunts(parsed, new URLSearchParams('limit=200'))
  assert.equal(allHunts.total, canonicalSourcePaths.length)
  assert.deepEqual(allHunts.items.map(hunt => hunt.id), parsed.queries.map(hunt => hunt.id).sort())
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
