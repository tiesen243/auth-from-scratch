'use server'

import { sha256 } from '@oslojs/crypto/sha2'
import { encodeHexLowerCase } from '@oslojs/encoding'
import { z } from 'zod'

import { Password } from '@/server/auth/password'
import { db } from '@/server/db'

const signUpSchema = z
  .object({
    name: z.string().min(1, 'Name is required'),
    email: z.string().email('Invalid email'),
    password: z
      .string()
      .min(8, 'Password must be at least 8 characters')
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/,
        'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
      ),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  })

export const signUp = async (
  formData: FormData,
): Promise<
  { success: true } | { success: false; fieldErros: Record<string, string[]> }
> => {
  try {
    const data = signUpSchema.parse(Object.fromEntries(formData))

    const image = encodeHexLowerCase(sha256(new TextEncoder().encode(data.email)))
    const password = await new Password().hash(data.password)

    await db.user.create({
      data: {
        email: data.email,
        name: data.name,
        password,
        image: `https://gravatar.com/avatar/${image}?d=identicon`,
      },
    })
    return { success: true }
  } catch (error) {
    if (error instanceof z.ZodError)
      return {
        success: false,
        fieldErros: error.flatten().fieldErrors as Record<string, string[]>,
      }
    return { success: false, fieldErros: {} }
  }
}
