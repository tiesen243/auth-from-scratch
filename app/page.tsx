import { auth } from '@/server/auth'

export default async function HomePage() {
  const session = await auth()

  return (
    <main className="container">
      <pre>{JSON.stringify(session, null, 2)}</pre>
    </main>
  )
}
