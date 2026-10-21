import { readHuntingBundle,artifactResponse,unavailableResponse } from '@/lib/hunting-artifacts'
export const runtime='nodejs'
export async function GET(request:Request) {
  try {const b=await readHuntingBundle();return artifactResponse(request,b,b)}
  catch {return unavailableResponse()}
}
