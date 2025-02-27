'use client'

import { useSession } from '@/hooks/use-session'

export default function ClientPage() {
  const { session, isLoading } = useSession()
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center gap-4 py-4">
      {isLoading ? (
        <p>Loading...</p>
      ) : (
        <pre className="mx-auto w-svh max-w-md overflow-x-auto">
          {JSON.stringify(session, null, 2)}
        </pre>
      )}
    </main>
  )
}
