import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'

import { Session } from '@/server/auth/session'

export const middleware = async (req: NextRequest) => {
  const _session = await new Session().validateSessionToken(
    req.cookies.get('auth_token')?.value ?? '',
  )

  return NextResponse.next()
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, sitemap.xml, robots.txt (metadata files)
     */
    '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
  ],
}
