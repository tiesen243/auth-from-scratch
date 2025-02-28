import { auth } from '@/server/auth'
import { SignInForm, SignOutButton } from './page.client'

export default async function HomePage() {
  const session = await auth()

  return (
    <main className="flex min-h-dvh flex-col items-center justify-center gap-4 py-4">
      {session.user ? (
        <>
          <pre className="mx-auto w-svh max-w-md overflow-x-auto">
            {JSON.stringify(session, null, 2)}
          </pre>

          <SignOutButton />
        </>
      ) : (
        <SignInForm />
      )}
    </main>
  )
}
