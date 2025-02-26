import type { OAuth2Tokens } from 'arctic'
import { cookies } from 'next/headers'
import { generateCodeVerifier, generateState } from 'arctic'
import { z } from 'zod'

import type { SessionResult } from '@/server/auth/session'
import { env } from '@/env'
import { Password } from '@/server/auth/password'
import { Session } from '@/server/auth/session'
import { db } from '@/server/db'

class AuthClass {
  private readonly db: typeof db = db
  private readonly session: Session = new Session()
  private readonly TOKEN_KEY: string = 'auth_token'

  private readonly providers: Providers

  constructor(args: { providers: Providers }) {
    this.providers = args.providers
  }

  public async auth(req?: Request): Promise<SessionResult> {
    let authToken: string | undefined

    if (req) {
      const cookies = this.parsedCookies(req.headers)
      authToken =
        cookies[this.TOKEN_KEY] ??
        req.headers.get('Authorization')?.replace('Bearer ', '')
    } else {
      authToken = (await cookies()).get(this.TOKEN_KEY)?.value
    }

    if (!authToken) return { expires: new Date() }

    return await this.session.validateSessionToken(authToken)
  }

  public async handlers(req: Request): Promise<Response> {
    const url = new URL(req.url)

    let response: Response = new Response('Not found', { status: 404 })

    switch (req.method) {
      case 'OPTIONS':
        response = new Response('', { status: 204 })
        break
      case 'GET':
        if (url.pathname === '/api/auth') {
          const session = await this.auth(req)
          response = new Response(JSON.stringify(session))
        } else if (url.pathname.startsWith('/api/auth/oauth')) {
          const isCallback = url.pathname.endsWith('/callback')

          if (!isCallback) {
            const provider = String(url.pathname.split('/').pop())
            const state = generateState()
            const codeVerifier = generateCodeVerifier()
            const authorizationUrl = this.providers[provider]?.createAuthorizationURL(
              state,
              codeVerifier,
            )

            if (!authorizationUrl) {
              response = new Response('Provider not found', { status: 404 })
            } else {
              response = new Response('', { status: 302 })
              response.headers.set('Location', authorizationUrl.toString())
              response.headers.set('Set-Cookie', `oauth_state=${state}; Path=/`)

              response.headers.set(
                'Set-Cookie',
                `oauth_state=${state}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax}`,
              )
              response.headers.append(
                'Set-Cookie',
                `code_verifier=${codeVerifier}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax}`,
              )
            }
          } else {
            const cookies = this.parsedCookies(req.headers)

            const provider = String(url.pathname.split('/').slice(-2)[0])
            const code = url.searchParams.get('code')
            const state = url.searchParams.get('state')
            const storedState = cookies.oauth_state
            const codeVerifier = cookies.code_verifier ?? ''

            try {
              if (!code || !state || state !== storedState)
                throw new Error('Invalid state')

              const { validateAuthorizationCode, fetchUserUrl, mapUser } =
                this.providers[provider] ?? {}
              if (!validateAuthorizationCode || !fetchUserUrl || !mapUser)
                throw new Error('Provider not found')

              const verifiedCode = await validateAuthorizationCode(code, codeVerifier)

              const token = verifiedCode.accessToken()

              const res = await fetch(fetchUserUrl, {
                headers: { Authorization: `Bearer ${token}` },
              })
              if (!res.ok) throw new Error(`Failed to fetch user data from ${provider}`)

              const user = await this.createUser(mapUser((await res.json()) as never))
              const session = await this.session.createSession(user.id)

              response = new Response('', { status: 302 })

              response.headers.set('Location', '/')
              response.headers.set(
                'Set-Cookie',
                `auth_token=${session.sessionToken}; HttpOnly; Path=/; SameSite=Lax; Expires=${session.expires.toUTCString()}${env.NODE_ENV === 'production' ? '; Secure' : ''}`,
              )
              response.headers.append(
                'Set-Cookie',
                `oauth_state=; HttpOnly; Path=/; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT${env.NODE_ENV === 'production' ? '; Secure' : ''}`,
              )
              response.headers.append(
                'Set-Cookie',
                `code_verifier=; HttpOnly; Path=/; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT${env.NODE_ENV === 'production' ? '; Secure' : ''}`,
              )
            } catch (error) {
              if (error instanceof Error)
                response = new Response(JSON.stringify({ error: error.message }), {
                  status: 400,
                })
              else
                response = new Response(JSON.stringify({ error: 'An error occurred' }), {
                  status: 500,
                })
            }
          }
        }
        break
      case 'POST':
        if (url.pathname === '/api/auth/sign-out') {
          const cookies = this.parsedCookies(req.headers)
          const token =
            cookies[this.TOKEN_KEY] ??
            req.headers.get('Authorization')?.replace('Bearer ', '') ??
            ''
          await this.session.invalidateSessionToken(token)
          response = new Response('', { status: 204 })
        }
        break
    }

    this.setCorsHeaders(response)
    return response
  }

  public async signOut(req?: Request) {
    let token: string

    if (req) {
      const cookies = this.parsedCookies(req.headers)
      token =
        cookies[this.TOKEN_KEY] ??
        req.headers.get('Authorization')?.replace('Bearer ', '') ??
        ''
    } else {
      token = (await cookies()).get(this.TOKEN_KEY)?.value ?? ''
    }

    await this.session.invalidateSessionToken(token)
  }

  private parsedCookies(headers: Headers): Record<string, string> {
    const cookiesHeader = headers.get('cookie')
    if (!cookiesHeader) return {}

    return cookiesHeader.split(';').reduce((acc, cookie) => {
      const [name, value] = cookie.split('=') as [string, string]
      return { ...acc, [name.trim()]: value }
    }, {})
  }

  public async signInWithCredentials(
    data: z.infer<typeof credentialsSchema>,
  ): Promise<
    | { success: false; fieldErrors: Record<string, string[]> }
    | { success: true; session: { sessionToken: string; expires: Date } }
  > {
    const parsedData = credentialsSchema.safeParse(data)
    if (!parsedData.success)
      return { success: false, fieldErrors: parsedData.error.flatten().fieldErrors }

    const { email, password } = parsedData.data

    const user = await this.db.user.findUnique({ where: { email } })
    if (!user) throw new Error('User not found')
    if (!user.password) throw new Error('User has no password')

    const passwordMatch = await new Password().verifyPassword(password, user.password)
    if (!passwordMatch) throw new Error('Invalid password')

    return { success: true, session: await this.session.createSession(user.id) }
  }

  private async createUser(data: {
    provider: string
    providerAccountId: string
    providerAccountName: string
    email: string
    image: string
  }) {
    const { provider, providerAccountId, providerAccountName, email, image } = data

    const existingAccount = await db.account.findUnique({
      where: { provider_providerAccountId: { provider, providerAccountId } },
    })

    if (existingAccount) {
      const user = await db.user.findUnique({
        where: { id: existingAccount.userId },
      })
      if (!user) throw new Error(`Failed to sign in with ${provider}`)
      return user
    }

    const accountData = {
      provider,
      providerAccountId,
      providerAccountName,
    }

    return await db.user.upsert({
      where: { email },
      update: { accounts: { create: accountData } },
      create: {
        email,
        name: providerAccountName,
        image,
        accounts: { create: accountData },
      },
    })
  }

  private setCorsHeaders(res: Response) {
    res.headers.set('Content-Type', 'application/json')
    res.headers.set('Access-Control-Allow-Origin', '*')
    res.headers.set('Access-Control-Request-Method', '*')
    res.headers.set('Access-Control-Allow-Methods', 'OPTIONS, GET, POST')
    res.headers.set('Access-Control-Allow-Headers', '*')
  }
}

type Providers = Record<
  string,
  {
    createAuthorizationURL: (state: string, codeVerifier: string) => URL
    validateAuthorizationCode: (
      code: string,
      codeVerifier: string,
    ) => Promise<OAuth2Tokens>
    fetchUserUrl: string
    mapUser: (user: never) => {
      provider: string
      providerAccountId: string
      providerAccountName: string
      email: string
      image: string
    }
  }
>

const credentialsSchema = z.object({
  email: z.string().email(),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/,
      'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
    ),
})

export const Auth = (args: { providers: Providers }) => {
  const authInstance = new AuthClass(args)

  return {
    auth: (req?: Request) => authInstance.auth(req),
    signInWithCredentials: (data: z.infer<typeof credentialsSchema>) =>
      authInstance.signInWithCredentials(data),
    signOut: (req?: Request) => authInstance.signOut(req),
    handlers: (req: Request) => authInstance.handlers(req),
  }
}
