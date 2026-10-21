import { NextResponse } from 'next/server'
import { readHuntingBundle,artifactResponse,unavailableResponse } from '@/lib/hunting-artifacts'
import { listHunts } from '@/lib/hunting-contracts'
export const runtime='nodejs'
export async function GET(request:Request) {
  let bundle
  try {bundle=await readHuntingBundle()} catch {return unavailableResponse()}
  try {return artifactResponse(request,bundle,listHunts(bundle,new URL(request.url).searchParams))}
  catch {return NextResponse.json({error:'invalid_hunt_filters'},{status:400})}
}
