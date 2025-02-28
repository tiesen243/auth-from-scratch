'use client'

import type { User } from '@prisma/client'
import * as React from 'react'
import { useRouter } from 'next/navigation'
import { useQuery } from '@tanstack/react-query'

interface SessionContextValue {
  session: {
    user?: User
    expres: Date
  }
  isLoading: boolean
  refresh: () => Promise<void>
}

const SessionContext = React.createContext<SessionContextValue | undefined>(undefined)

export const useSession = () => {
  const context = React.useContext(SessionContext)
  if (!context) throw new Error('useSession must be used within a SessionProvider')
  return context
}

export const SessionProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const router = useRouter()

  const session = useQuery({
    queryKey: ['auth'],
    queryFn: async () => {
      const res = await fetch('/api/auth')
      if (!res.ok) throw new Error('Not authenticated')
      return res.json() as Promise<SessionContextValue['session']>
    },
  })

  const refresh = async () => {
    await session.refetch()
    router.refresh()
  }

  return (
    <SessionContext.Provider
      value={{
        session: session.data ?? { expres: new Date() },
        isLoading: session.isLoading,
        refresh,
      }}
    >
      {children}
    </SessionContext.Provider>
  )
}
