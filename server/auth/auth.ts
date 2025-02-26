import { cookies } from 'next/headers'
import { z } from 'zod'

import type { SessionResult } from '@/server/auth/session'
import { Session } from '@/server/auth/session'
import { db } from '@/server/db'
import { Password } from './password'

class AuthClass {
  private readonly db: typeof db = db
  private readonly session: Session = new Session()
  private readonly TOKEN_KEY: string = 'auth_token'

  private readonly providers: Providers
  private readonly baseUrl: string

  constructor(args: { providers: Providers; baseUrl: string }) {
    this.providers = args.providers
    this.baseUrl = args.baseUrl
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

  public async signIn(args: {
    provider: string
    data?: z.infer<typeof credentialsSchema>
  }) {
    switch (args.provider) {
      case 'credentials':
        if (!args.data) throw new Error('No data provided')
        return await this.signInWithCredentials(args.data)
      default:
        throw new Error('Invalid provider')
    }
  }

  private parsedCookies(headers: Headers): Record<string, string> {
    const cookiesHeader = headers.get('cookie')
    if (!cookiesHeader) return {}

    return cookiesHeader.split(';').reduce((acc, cookie) => {
      const [name, value] = cookie.split('=') as [string, string]
      return { ...acc, [name.trim()]: value }
    }, {})
  }

  private async signInWithCredentials(
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
    scopes: string[]
    fetchUserUrl: string
    mapUser: (user: unknown) => {
      providerAccountId: string
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

export const Auth = (args: { providers: Providers; baseUrl: string }) => {
  const authInstance = new AuthClass(args)

  return {
    auth: (req?: Request) => authInstance.auth(req),
    signIn: (args: { provider: string; data?: z.infer<typeof credentialsSchema> }) =>
      authInstance.signIn(args),
    handlers: (req: Request) => authInstance.handlers(req),
  }
}
