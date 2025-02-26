import { cache } from 'react'
import { cookies } from 'next/headers'

import type { SessionResult } from '@/server/auth/session'
import { Session } from '@/server/auth/session'

const TOKEN_KEY = 'auth_token'

export const auth = cache(async (req?: Request): Promise<SessionResult> => {
  let authToken: string | undefined

  if (req) {
    const cookies = parsedCookies(req.headers)
    authToken =
      cookies[TOKEN_KEY] ?? req.headers.get('Authorization')?.replace('Bearer ', '')
  } else {
    authToken = (await cookies()).get(TOKEN_KEY)?.value
  }

  if (!authToken) return { expires: new Date() }

  return await new Session().validateSessionToken(authToken)
})

const parsedCookies = (headers: Headers): Record<string, string> => {
  const cookiesHeader = headers.get('cookie')
  if (!cookiesHeader) return {}

  return cookiesHeader.split(';').reduce((acc, cookie) => {
    const [name, value] = cookie.split('=') as [string, string]
    return { ...acc, [name.trim()]: value }
  }, {})
}
