'use server'

import { cache } from 'react'
import { Discord, Google } from 'arctic'

import { env } from '@/env'
import { getBaseUrl } from '@/lib/utils'
import { Auth } from '@/server/auth/auth'

const discord = new Discord(
  env.DISCORD_CLIENT_ID,
  env.DISCORD_CLIENT_SECRET,
  `${getBaseUrl()}/api/auth/oauth/discord/callback`,
)

const google = new Google(
  env.GOOGLE_CLIENT_ID,
  env.GOOGLE_CLIENT_SECRET,
  `${getBaseUrl()}/api/auth/oauth/google/callback`,
)

const {
  auth: uncachedAuth,
  signInWithCredentials,
  signOut,
  handlers,
} = Auth({
  providers: {
    discord: {
      createAuthorizationURL: (state, codeVerifier) =>
        discord.createAuthorizationURL(state, codeVerifier, ['identify', 'email']),
      validateAuthorizationCode: (code, codeVerifier) =>
        discord.validateAuthorizationCode(code, codeVerifier),
      fetchUserUrl: 'https://discord.com/api/users/@me',
      mapUser: (user: {
        id: string
        email: string
        username: string
        avatar: string
      }) => ({
        provider: 'discord',
        providerAccountId: user.id,
        providerAccountName: user.username,
        email: user.email,
        image: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`,
      }),
    },
    google: {
      createAuthorizationURL: (state, codeVerifier) =>
        google.createAuthorizationURL(state, codeVerifier, [
          'openid',
          'profile',
          'email',
        ]),
      validateAuthorizationCode: (code, codeVerifier) =>
        google.validateAuthorizationCode(code, codeVerifier),
      fetchUserUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
      mapUser: (user: { sub: string; email: string; name: string; picture: string }) => ({
        provider: 'google',
        providerAccountId: user.sub,
        providerAccountName: user.name,
        email: user.email,
        image: user.picture,
      }),
    },
  },
})

const auth = cache(uncachedAuth)

export { auth, signInWithCredentials, signOut, handlers }
