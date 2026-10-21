import { NextResponse } from 'next/server'
import { readHuntingBundle,artifactResponse,unavailableResponse } from '@/lib/hunting-artifacts'
import { getHunt,HuntNotFound } from '@/lib/hunting-contracts'
export const runtime='nodejs'
export async function GET(request:Request,{params}:{params:Promise<{id:string}>}) {
  let bundle
  try {bundle=await readHuntingBundle()} catch {return unavailableResponse()}
  try {return artifactResponse(request,bundle,getHunt(bundle,(await params).id))}
  catch(error) {return NextResponse.json({error:error instanceof HuntNotFound?'not_found':'invalid_hunt_id'},{status:error instanceof HuntNotFound?404:400})}
}
