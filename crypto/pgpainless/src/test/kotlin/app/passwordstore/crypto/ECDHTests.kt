/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ECDHTests {

  val pubKeyAscii = // "modernKeyRing"
    """  
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Comment: C68A 9140 9A00 3C55 5D8A  62A5 D3ED 03F9 FF75 68D4
    Comment: john doe <j.doe@example.com>
    
    mDMEaR7iehYJKwYBBAHaRw8BAQdA5XMRsc8HUXiJkjtOSCj86v+OeemU41U08Lmi
    2PQ3Tnm0HGpvaG4gZG9lIDxqLmRvZUBleGFtcGxlLmNvbT7CnwQTFgoAUQkQ0+0D
    +f91aNQWoQTGipFAmgA8VV2KYqXT7QP5/3Vo1AWCaR7iegKbAQUVCgkICwUWAgMB
    AAQLCQgHCScJAQkCCQMIAQKeCQWJCWYBgAKZAQAAFecBALy6FxELczpihvkVJPa2
    iaV7zDcfFBvX4KyTr506hxufAP4ixT59d/QRMWmuRN6QRkRcgduLaw2l/Hs/zBuV
    tQjHDsKfBBMWCgBRApsBBRUKCQgLBRYCAwEABAsJCAcJJwkBCQIJAwgBAp4JCRDT
    7QP5/3Vo1BahBMaKkUCaADxVXYpipdPtA/n/dWjUBYJpHuJ7BYkAAAAAApkBAAAK
    SQD9FpbJAinkmaeHluaKmiCp0HggoGF8aji9rDqSvUDtnWsA/i5I1eZ0rPvxZc6z
    pIbfRHdbdgOTmTZEOOz82GQVmsMLuDgEaR7iehIKKwYBBAGXVQEFAQEHQHc9W+J1
    IPl7nekdLrx5SLdvYnNNocULlqqLoDgN3fV4AwEIB8J4BBgWCgAqCRDT7QP5/3Vo
    1BahBMaKkUCaADxVXYpipdPtA/n/dWjUBYJpHuJ6ApsMAACh/AEA1r+JB8uhMX7N
    l4B3QOF9zLmUXhihRvE0tyY3cCCwUrYA/2yqF1mA8dHsDuDnWEUYxgX+ZpYBXr+P
    j9ZKl/HoNeIOuDMEaR7iehYJKwYBBAHaRw8BAQdAQPTWzF21MpuSRjclxeAS+lZH
    ulTwm/HsOaVpur8vSZ/CwC8EGBYKAKEJENPtA/n/dWjUFqEExoqRQJoAPFVdimKl
    0+0D+f91aNQFgmke4noCmwJ2IAQZFgoAHQWCaR7iehYhBMqKZfP+EDi1iRE58a14
    HgK5jFyDAAoJEK14HgK5jFyDoRUA/0GmLpBUVFSEdbSh+o7tz6xncAIjkm20LWIy
    PF81ilR9AP0a/MVoE9ivY7HK9uu79cc2Y5IratjiXRpamYqODQutAQAA848A/Ro1
    SfAfFAmMDfcbuKvpQEK/d4T3455End3ohd5TXb7VAP9/wMxzLJ1K5mE6LTQ5Hw4b
    m9XtYRYVHugI27XFacaFAg==
    =3yy3
    -----END PGP PUBLIC KEY BLOCK-----
    """.trimIndent()

  @Test
  fun getx9ParamsTest() {
    val cerificate = org.bouncycastle.openpgp.api.OpenPGPKeyReader().parseCertificate(pubKeyAscii.toByteArray())
    val pubKey = cerificate.getEncryptionKeys().first().getPGPPublicKey()

    assertTrue(pubKey.isEncryptionKey())

    val ecPubKey = pubKey.getPublicKeyPacket().getKey() as org.bouncycastle.bcpg.ECDHPublicBCPGKey 
	val x9Params = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByOIDLazy(ecPubKey.getCurveOID())

    assertNotNull(x9Params)
  }

}
