import { Opaque } from 'type-fest'
import * as crypto from 'crypto'
import base32 from 'nano-base32'
import * as miscreant from 'miscreant'

export const asBuffer = (bufOrStr: string | Buffer): Buffer =>
  Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(bufOrStr)

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

export const aesKeyWrap = (key: Buffer, kek: Buffer): Buffer => {
  const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex')
  const cipher = crypto.createCipheriv('id-aes128-wrap', kek, iv)
  const result = cipher.update(key)
  cipher.final()
  return result
}

export const aesKeyUnwrap = (key: Buffer, kek: Buffer): Buffer => {
  console.log(key.length, key)
  const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex')
  const decipher = crypto.createDecipheriv('id-aes128-wrap', kek, iv)
  const result = [decipher.update(key)]
  result.push(decipher.final())
  return Buffer.concat(result)
}

export const deriveMasterKeys = async (
  params: MasterkeyParams,
  password: string | Buffer,
) => {
  const kek: Buffer = await new Promise((res, rej) => {
    crypto.scrypt(
      asBuffer(password),
      params.scryptSalt,
      16,
      {
        N: params.scryptCostParam,
        r: params.scryptBlockSize,
        maxmem: 128 * params.scryptCostParam * params.scryptBlockSize * 2,
      },
      (err, derivedKey) => (err ? rej(err) : res(derivedKey)),
    )
  })
  console.log(kek.length, kek)
  const macMasterKey = aesKeyUnwrap(
    Buffer.from(params.hmacMasterKey, 'base64'),
    kek,
  )
  const encryptionMasterKey = aesKeyUnwrap(
    Buffer.from(params.primaryMasterKey, 'base64'),
    kek,
  )
  return { macMasterKey, encryptionMasterKey }
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
    )
    return base32.encode(
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
    )
    const plaintextName = base32.decode(ciphertextName)
    return Buffer.from(
      await aesSiv.open(base32.decode(ciphertextName), [asBuffer(parentDirId)]),
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
