import { cookies } from 'next/headers'

import { env } from '@/env'
import { auth } from '@/server/auth'
import { SignInForm } from './page.client'

export default async function HomePage() {
  const session = await auth()

  const setTokenAction = async (token: string, expires: Date) => {
    'use server'
    ;(await cookies()).set('auth_token', token, {
      httpOnly: true,
      path: '/',
      secure: env.NODE_ENV === 'production',
      sameSite: 'lax',
      expires,
    })
  }

  return (
    <main className="container">
      <pre>{JSON.stringify(session, null, 2)}</pre>

      {session.user ? <></> : <SignInForm setTokenAction={setTokenAction} />}
    </main>
  )
}
