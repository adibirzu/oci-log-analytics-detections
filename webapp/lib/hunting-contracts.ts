/** Tenant-neutral schema and lookup only: queries remain generator-owned. */
import { createHash } from 'node:crypto'
import { z } from 'zod'
const strings = z.array(z.string())
const sha = z.string().regex(/^[0-9a-f]{64}$/)
const fieldContract = z.object({status:z.enum(['ready','blocked']),required_fields:strings,unmapped_fields:strings,reasons:strings}).strict()
const huntSchema = z.object({
  id:z.string(), source_path:z.string().regex(/^hunting\/[a-z0-9][a-z0-9_-]*\.json$/),
  title:z.string(),description:z.string(),query:z.string().min(1),query_sha256:sha,
  severity:z.enum(['informational','low','medium','high','critical']),
  mitre_attack:z.record(z.unknown()),tags:strings,source_candidates:strings,field_contract:fieldContract,
  false_positives:strings,investigation_notes:strings,pack_ids:strings,dashboard_references:strings,
  provenance:z.record(z.unknown()),guidance:z.record(z.unknown()),evidence_class:z.literal('code-backed'),
}).strict()
const bundleSchema=z.object({schema_version:z.literal('1.0.0'),generated_at:z.string().datetime({offset:true}),
  generator:z.literal('scripts/generate_hunting_bundle.py'),content_digest:sha,input_digests:z.record(sha),
  packs:z.array(z.object({id:z.string(),title:z.string(),query_paths:strings}).strict()),queries:z.array(huntSchema),
}).strict()
export type HuntingBundle=z.infer<typeof bundleSchema>
export type Hunt=z.infer<typeof huntSchema>
export class HuntNotFound extends Error {}

export function canonicalJson(value: unknown): string {
  if(Array.isArray(value)) return '['+value.map(canonicalJson).join(',')+']'
  if(value!==null && typeof value==='object') {
    const record=value as Record<string,unknown>
    return '{'+Object.keys(record).sort().map(k=>JSON.stringify(k)+':'+canonicalJson(record[k])).join(',')+'}'
  }
  return JSON.stringify(value)
}
export function hash(value: string): string {return createHash('sha256').update(value).digest('hex')}
export function validateHuntingBundle(value: unknown): HuntingBundle {
  const b=bundleSchema.parse(value)
  const {content_digest:expected,generated_at,...content}=b
  void generated_at
  if(hash(canonicalJson(content))!==expected) throw new Error('Invalid content digest')
  const ids=new Set<string>()
  for(const q of b.queries) {
    if(ids.has(q.id)||q.id!=='hunt:'+q.source_path.slice(0,-5)||hash(q.query)!==q.query_sha256) throw new Error('Invalid query identity')
    ids.add(q.id)
    const packs=b.packs.filter(p=>p.query_paths.includes(q.source_path)).map(p=>p.id)
    if(JSON.stringify(packs)!==JSON.stringify(q.pack_ids)) throw new Error('Invalid query packs')
  }
  if(new Set(b.packs.map(p=>p.id)).size!==b.packs.length||b.packs.some(p=>p.query_paths.some(path=>!b.queries.some(q=>q.source_path===path)))) throw new Error('Invalid pack membership')
  return b
}
export function getHunt(b:HuntingBundle,id:string):Hunt {
  if(!/^hunt:hunting\/[a-z0-9][a-z0-9_-]*$/.test(id)) throw new Error('Invalid hunt ID')
  const q=b.queries.find(q=>q.id===id)
  if(!q) throw new HuntNotFound('Hunt not found')
  return q
}
export function listHunts(b:HuntingBundle,params:URLSearchParams) {
  const allowed=new Set(['pack','source','tactic','technique','severity','readiness','offset','limit'])
  for(const [key,val] of params) if(!allowed.has(key)||params.getAll(key).length!==1||!val.trim()) throw new Error('Invalid filters')
  const offset=Number(params.get('offset')??0),limit=Number(params.get('limit')??50)
  if(!Number.isInteger(offset)||offset<0||!Number.isInteger(limit)||limit<1||limit>200) throw new Error('Invalid pagination')
  const ready=params.get('readiness'),severity=params.get('severity')
  if(ready&&!['ready','blocked'].includes(ready)||severity&&!['informational','low','medium','high','critical'].includes(severity)) throw new Error('Invalid filter')
  const rows=b.queries.filter(q=>{
    const values:Record<string,string[]>={pack:q.pack_ids,source:q.source_candidates,tactic:(q.mitre_attack.tactics??[]) as string[],technique:(q.mitre_attack.techniques??[]) as string[],severity:[q.severity],readiness:[q.field_contract.status]}
    return Object.entries(values).every(([key,vals])=>!params.has(key)||vals.includes(params.get(key)!))
  }).sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0)
  return {schema_version:b.schema_version,content_digest:b.content_digest,total:rows.length,offset,limit,
    items:rows.slice(offset,offset+limit).map(({query,...metadata})=>{void query;return metadata})}
}
