import test from 'ava'
import * as fs from 'fs'

import { createFileNameDecryptor, deriveMasterKeys } from '../src/index'

test(`deriveMasterKey decodes CryptorImplTest#writeKeysToMasterkeyFile`, async (t) => {
  const keys = await deriveMasterKeys(
    {
      scryptSalt: 'AAAAAAAAAAA=',
      scryptCostParam: 32768,
      scryptBlockSize: 8,
      primaryMasterKey:
        'bOuDTfSpTHJrM4G321gts1QL+TFAZ3I6S/QHwim39pz+t+/K9IYy6g==',
      hmacMasterKey: 'bOuDTfSpTHJrM4G321gts1QL+TFAZ3I6S/QHwim39pz+t+/K9IYy6g==',
      versionMac: 'iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=',
      version: 3,
    },
    'asd',
  )
  const ZERO_KEY = Buffer.alloc(32)
  t.is(keys.encryptionMasterKey, ZERO_KEY)
  t.is(keys.encryptionMasterKey, ZERO_KEY)
})

test(`WIP`, async (t) => {
  const password = `testpassword123`
  const keyParams = JSON.parse(
    fs.readFileSync(__dirname + '/test-vault/masterkey.cryptomator', 'utf-8'),
  )

  const vaultKeys = await deriveMasterKeys(keyParams, password)
  const decryptFileName = createFileNameDecryptor(
    vaultKeys.encryptionMasterKey,
    vaultKeys.macMasterKey,
  )
  console.log(
    decryptFileName(
      `4SNFVJAW3FPDXMTAJNRMWX67FWHWT36VFOGMJMMCPPVGKEEJMEUJNOI=`,
      '',
    ),
  )
})
