import { hash, verify } from '@node-rs/argon2'

export class Password {
  public async hash(password: string): Promise<string> {
    return await hash(password, {
      memoryCost: 19456,
      timeCost: 2,
      outputLen: 32,
      parallelism: 1,
    })
  }

  public async verify(password: string, hash: string): Promise<boolean> {
    return await verify(hash, password)
  }
}
