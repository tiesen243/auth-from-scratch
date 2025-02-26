'use client'

import { useState } from 'react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { signIn } from '@/server/auth'

export const SignInForm: React.FC<{
  setTokenAction: (token: string, expires: Date) => Promise<void>
}> = ({ setTokenAction }) => {
  const [fieldErrors, setErrors] = useState<Record<string, string[]>>({})

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)

    try {
      const res = await signIn({
        provider: 'credentials',
        data: {
          email: form.get('email') as string,
          password: form.get('password') as string,
        },
      })

      if (!res.success) setErrors(res.fieldErrors)
      else {
        await setTokenAction(res.session.sessionToken, res.session.expires)
        toast.success("You're signed in")
      }
    } catch (error) {
      if (error instanceof Error) toast.error(error.message)
      else toast.error('An error occurred')
    }
  }

  return (
    <form onSubmit={handleSubmit} className="mx-auto grid max-w-md gap-4">
      <fieldset className="grid gap-2">
        <Label htmlFor="email">Email</Label>
        <Input type="email" id="email" name="email" />
        <p className="text-destructive text-xs">{fieldErrors.email}</p>
      </fieldset>

      <fieldset className="grid gap-2">
        <Label htmlFor="password">Password</Label>
        <Input type="password" id="password" name="password" />
        <p className="text-destructive text-xs">{fieldErrors.password}</p>
      </fieldset>

      <Button type="submit">Sign In</Button>
    </form>
  )
}
