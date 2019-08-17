import * as fs from 'fs'

import { createFileNameDecryptor, deriveMasterKeys } from './index'

const password = `testpassword123`

  // Run
;(async () => {
  const keyParams = JSON.parse(
    fs.readFileSync(__dirname + '/test-vault/masterkey.cryptomator', 'utf-8'),
  )
  const vaultKeys = await deriveMasterKeys(keyParams, password)
  console.log(vaultKeys)
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
})().catch((e) => {
  console.error(e)
  process.exit(1)
})
