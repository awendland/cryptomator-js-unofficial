import { Opaque } from 'type-fest'
import * as crypto from 'crypto'
import baseX from 'base-x'
import * as miscreant from 'miscreant'
import * as openpgp from 'openpgp'

export const asBuffer = (bufOrStr: string | Buffer): Buffer =>
  Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(bufOrStr)

// https://guava.dev/releases/16.0/api/docs/com/google/common/io/BaseEncoding.html
// TODO this isn't decoding correctly (probably, it's not handling `=` padding)
const base32guava = baseX('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')

/*
 * MasterKey Operations
 */

export type MasterkeyParams = {
  scryptSalt: string
  scryptCostParam: number
  scryptBlockSize: number
  primaryMasterKey: string
  hmacMasterKey: string
  versionMac: string
  version: number
}

export type VaultKeys = {
  macMasterKey: Buffer
  encryptionMasterKey: Buffer
}

// export const aesKeyWrap = (key: Buffer, kek: Buffer): Buffer => {
//   const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex')
//   const cipher = crypto.createCipheriv('id-aes128-wrap', kek, iv)
//   const result = cipher.update(key)
//   cipher.final()
//   return result
// }

// export const aesKeyUnwrap = (key: Buffer, kek: Buffer): Buffer => {
//   console.log(key.length, key)
//   const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex')
//   console.log(kek.toString('hex'))
//   const decipher = crypto.createDecipheriv('id-aes128-wrap', kek, iv)
//   return Buffer.concat([decipher.update(key), decipher.final()])
// }

export const deriveMasterKeys = async (
  params: MasterkeyParams,
  password: string | Buffer,
) => {
  const kek: Buffer = await new Promise((res, rej) => {
    crypto.scrypt(
      asBuffer(password),
      Buffer.from(params.scryptSalt, 'base64'),
      32,
      {
        N: params.scryptCostParam,
        r: params.scryptBlockSize,
        maxmem: 128 * params.scryptCostParam * params.scryptBlockSize * 2,
      },
      (err, derivedKey) => (err ? rej(err) : res(derivedKey)),
    )
  })
  const unwrap = (key: string) =>
    Buffer.from(
      openpgp.crypto.aes_kw.unwrap(
        (kek as unknown) as string, // TODO fix @types/openpgp
        (Buffer.from(key, 'base64') as unknown) as string,
      ),
    )
  return {
    macMasterKey: unwrap(params.hmacMasterKey),
    encryptionMasterKey: unwrap(params.primaryMasterKey),
  }
}

/*
 * Filename Operations
 */
export const createFileNameEncryptor = (
  encMasterKey: Buffer,
  macMasterKey: Buffer,
) =>
  async function encryptFileName(
    cleartextName: string | Buffer,
    parentDirId: string | Buffer,
  ): Promise<string> {
    const aesSiv = await miscreant.SIV.importKey(
      Buffer.concat([encMasterKey, macMasterKey]),
      'AES-SIV',
      new miscreant.PolyfillCryptoProvider(),
    )
    return base32guava.encode(
      await aesSiv.seal(asBuffer(cleartextName), [asBuffer(parentDirId)]),
    )
  }

export const createFileNameDecryptor = (
  encMasterKey: Buffer,
  macMasterKey: Buffer,
) =>
  async function decryptFileName(
    ciphertextName: string,
    parentDirId: string | Buffer,
  ): Promise<Buffer> {
    const aesSiv = await miscreant.SIV.importKey(
      Buffer.concat([encMasterKey, macMasterKey]),
      'AES-SIV',
      new miscreant.PolyfillCryptoProvider(),
    )
    const plaintextName = base32guava.decode(ciphertextName.replace('=', ''))
    return Buffer.from(
      await aesSiv.open(plaintextName, [asBuffer(parentDirId)]),
    )
  }

// const shasum = crypto.createHash('sha1')
// const dirIdHash = base32.encode(
//   shasum.update(await aesSiv.seal(dirId, [])).digest(),
// )
// return dirIdHash.substr(0, 2) + '/' + dirIdHash.substr(2, 30)

/*
 * General Vault Operations
 */

export type VaultConfig = {
  rootPath: string
  masterkeyParams: MasterkeyParams
  password: string
}

export type AESSIVFunc = (
  data: Buffer | string,
  associatedData: Buffer | string | null,
  encMasterKey: Buffer,
  macMasterKey: Buffer,
) => Buffer

export class Vault {
  constructor(public config: VaultConfig, aesSiv: AESSIVFunc) {}
}
