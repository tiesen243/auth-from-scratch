'use server'

import { cache } from 'react'

import { getBaseUrl } from '@/lib/utils'
import { Auth } from '@/server/auth/auth'

const {
  auth: uncachedAuth,
  signIn,
  signOut,
  handlers,
} = Auth({
  providers: {},
  baseUrl: getBaseUrl(),
})

const auth = cache(uncachedAuth)

export { auth, signIn, signOut, handlers }
