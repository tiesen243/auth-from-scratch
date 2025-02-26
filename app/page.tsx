import { cookies } from 'next/headers'

import { env } from '@/env'
import { auth } from '@/server/auth'
import { SignInForm, SignOutButton } from './page.client'

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

  const deleteTokenAction = async () => {
    'use server'
    ;(await cookies()).delete('auth_token')
  }

  return (
    <main className="container flex flex-col items-center gap-4 py-4">
      <pre className="mx-auto w-svh max-w-md overflow-x-auto">
        {JSON.stringify(session, null, 2)}
      </pre>

      {session.user ? (
        <SignOutButton deleteTokenAction={deleteTokenAction} />
      ) : (
        <SignInForm setTokenAction={setTokenAction} />
      )}
    </main>
  )
}
