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
import { signInWithCredentials } from '@/server/auth'

export const SignInForm: React.FC<{
  setTokenAction: (token: string, expires: Date) => Promise<void>
}> = ({ setTokenAction }) => {
  const { refresh } = useSession()

  const [fieldErrors, setErrors] = useState<Record<string, string[]> | undefined>({})

  const { mutate, isPending } = useMutation({
    mutationFn: async (formData: FormData) => {
      const res = await signInWithCredentials({
        email: formData.get('email') as string,
        password: formData.get('password') as string,
      })
      if (!res.success) setErrors(res.fieldErrors)
      else {
        setErrors({})
        return res.session
      }
    },
    onSuccess: async (session) => {
      await setTokenAction(session?.sessionToken ?? '', session?.expires ?? new Date())
      toast.success("You're signed in")
      await refresh()
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

        <form className="grid w-full grid-cols-2 gap-4 *:w-full">
          <Button variant="outline" formAction="/api/auth/oauth/google">
            Login with Google
          </Button>

          <Button variant="outline" formAction="/api/auth/oauth/discord">
            Login with Discord
          </Button>
        </form>
      </CardFooter>
    </Card>
  )
}

export const SignOutButton: React.FC<{ deleteTokenAction: () => Promise<void> }> = ({
  deleteTokenAction,
}) => {
  const { signOut } = useSession()

  return (
    <Button
      onClick={async () => {
        signOut()
        await deleteTokenAction()
        toast.success("You're signed out")
      }}
    >
      Sign out
    </Button>
  )
}
