'use client'

import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useSession } from '@/hooks/use-session'
import { signIn, signOut } from '@/server/auth'

export const SignInForm: React.FC = () => {
  const { refresh } = useSession()
  const [fieldErrors, setErrors] = useState<Record<string, string[]> | undefined>({})

  const { mutate, isPending } = useMutation({
    mutationFn: async (formData: FormData) => {
      const res = await signIn('credentials', {
        email: formData.get('email') as string,
        password: formData.get('password') as string,
      })

      if (!res?.success) setErrors(res?.fieldErrors)
      else {
        setErrors({})
        return res
      }
    },
    onSuccess: async (data) => {
      await refresh()
      toast.success(data?.message)
    },
    onError: (err) => toast.error(err.message),
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Sign In</CardTitle>
        <CardDescription>
          Enter your credentials to sign in to your account
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form action={mutate} className="mx-auto grid w-svh max-w-md gap-4">
          <fieldset className="grid gap-2" disabled={isPending}>
            <Label htmlFor="email">Email</Label>
            <Input type="email" id="email" name="email" />
            <p className="text-destructive text-xs">{fieldErrors?.email}</p>
          </fieldset>

          <fieldset className="grid gap-2" disabled={isPending}>
            <Label htmlFor="password">Password</Label>
            <Input type="password" id="password" name="password" />
            <p className="text-destructive text-xs">{fieldErrors?.password}</p>
          </fieldset>

          <Button disabled={isPending}>Sign In</Button>
        </form>
      </CardContent>

      <CardFooter className="w-full flex-col gap-4">
        <div className="after:border-border relative w-full text-center text-sm after:absolute after:inset-0 after:top-1/2 after:z-0 after:flex after:items-center after:border-t">
          <span className="bg-background text-muted-foreground relative z-10 px-2">
            Or continue with
          </span>
        </div>

        <div className="grid w-full grid-cols-2 gap-4 *:w-full">
          <Button variant="outline" onClick={async () => signIn('discord')}>
            Login with Discord
          </Button>
          <Button variant="outline" onClick={async () => signIn('google')}>
            Login with Google
          </Button>
        </div>
      </CardFooter>
    </Card>
  )
}

export const SignOutButton: React.FC = () => {
  const { refresh } = useSession()

  return (
    <Button
      onClick={async () => {
        await signOut()
        await refresh()
        toast.success("You're signed out")
      }}
    >
      Sign out
    </Button>
  )
}
