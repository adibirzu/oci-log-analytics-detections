import 'server-only'
import path from 'node:path'
import { readFile, stat, readdir } from 'node:fs/promises'
import { NextResponse } from 'next/server'
import { canonicalJson, hash, validateHuntingBundle, type HuntingBundle } from './hunting-contracts'
const root=process.env.LOGAN_DETECTIONS_REPO ? path.resolve(process.env.LOGAN_DETECTIONS_REPO) : path.resolve(process.cwd(),'..')
export const MAX_BUNDLE_BYTES=5*1024*1024
function withoutTimestamps(value:unknown):unknown {
  if(Array.isArray(value)) return value.map(withoutTimestamps)
  if(value!==null&&typeof value==='object') return Object.fromEntries(Object.entries(value).filter(([k])=>k!=='generated_at').map(([k,v])=>[k,withoutTimestamps(v)]))
  return value
}
export async function readHuntingBundle():Promise<HuntingBundle> {
  const filename=path.join(root,'queries/hunting_integration_bundle.json')
  if((await stat(filename)).size>MAX_BUNDLE_BYTES) throw new Error('oversized')
  const b=validateHuntingBundle(JSON.parse(await readFile(filename,'utf8')))
  const current=(await readdir(path.join(root,'queries/hunting'))).filter(p=>p.endsWith('.json')).map(p=>'queries/hunting/'+p).sort()
  const recorded=Object.keys(b.input_digests).filter(p=>p.startsWith('queries/hunting/')).sort()
  if(JSON.stringify(current)!==JSON.stringify(recorded)) throw new Error('stale')
  // Input paths are allowlisted, never selected by a query parameter or a bundle path.
  const inputs=['config/hunting_packs.json','config/hunting_reference_candidates.json','config/threat_intel_sources.json','queries/catalog.json','queries/log_source_field_dictionary.json','queries/dashboard_inventory.json','schemas/hunting_integration_bundle.schema.json','scripts/hunting_bundle.py','scripts/field_dictionary.py','scripts/hunting_fields.py','scripts/hunting_schema.py',...current]
  if(Object.keys(b.input_digests).length!==inputs.length) throw new Error('stale')
  await Promise.all(inputs.map(async relative=>{
    const text=await readFile(path.join(root,relative),'utf8')
    const digest=relative.endsWith('.json')?hash(canonicalJson(withoutTimestamps(JSON.parse(text)))):hash(text)
    if(b.input_digests[relative]!==digest) throw new Error('stale')
  }))
  return b
}
export function artifactResponse(request:Request,bundle:HuntingBundle,body:unknown):Response {
  const etag='"'+bundle.content_digest+'"'
  const headers={'ETag':etag,'Cache-Control':'no-cache'}
  if(request.headers.get('if-none-match')?.split(',').map(s=>s.trim()).includes(etag)) return new Response(null,{status:304,headers})
  const text=JSON.stringify(body)
  if(Buffer.byteLength(text)>MAX_BUNDLE_BYTES) return NextResponse.json({error:'response_too_large',hint:'Use paginated /api/forge/hunts'},{status:413})
  return new Response(text,{headers:{...headers,'Content-Type':'application/json'}})
}
export function unavailableResponse() {return NextResponse.json({error:'hunting_artifact_unavailable'},{status:503})}
