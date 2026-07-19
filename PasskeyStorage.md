# Passkey storage

## File name convention
````
path/to/{Relying Party ID}/{Credential ID (64 hexadecimal figures)}.gpg
````
e. g. `path/to/webauthn.io/a1b2c3d4...9f.gpg`

## File format
Binary passkey data is stored as a Base64URL-encoded string on the first line of the password file. Just like in traditional `pass` files, the passkey data can be followed by additional lines containing TOTP data, `key: value` pairs, or freeform text. Freeform text is separated from the previous structured content by an empty line.

## Passkey data format
Passkey credentials are first serialized as CBOR binary data with keys sorted lexicographically and then encoded into a Base64URL string. The input to CBOR serialisation is as follows:
````kotlin
{
  "id": ByteArray,          // credential ID (32 bytes)
  "rp": {                   // relying party info
    "id": String,           //   "example.com",
    "name": String?,        //   "Example Ltd.", may be null or missing
  },
  "user": {                 // credential owner info
    "id": ByteArray,        //   user handle, as sent by relying party
    "name": String,         //   log-in name, e. g. "alice.doe@example.com", "alice"
    "display_name": String? //   "Alice Doe", may be null or missing
  },
  "sign_count": Long,       // kept at 0 in APS to allow for cloned passkey
  "alg": Long,              // COSE algorithm identifier: ES256 (-7), Ed25519 (-8) or RS256 (-257)
  "private_key": ByteArray, // "raw" private key bytes, see below
  "created": Long,          // seconds since Epoch, java.time.Instant.now().getEpochSecond()
  "zone": String,           // time zone info string, java.time.ZoneId.systemDefault().toString()
}
````

## Key data in `private_key`
The raw bytes stored in the `private_key` field are obtained from `java.security.PrivateKey` as follows:
````kotlin
import java.security.PrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory

/* ECC P-256 private key as BigInteger scalar, converted to zero-padded, size 32 ByteArray
 * with leading signum byte stripped */
fun getES256PrivateKeyRawBytes(privateKey: PrivateKey): ByteArray =
  (ByteArray(32) + (privateKey as ECPrivateKey).s.toByteArray()).let {
    it.copyOfRange(it.size - 32, it.size)
  }

// Ed25519 private key, converted to size 32 ByteArray using BouncyCastle
fun getEd25519PrivateKeyRawBytes(privateKey: PrivateKey): ByteArray =
  (PrivateKeyFactory.createKey(privateKey.encoded) as Ed25519PrivateKeyParameters).encoded

// RSA-2048 private key, with modulus and exponent concatenated to size 512 ByteArray
fun getRS256PrivateKeyRawBytes(privateKey: PrivateKey): ByteArray {
  val rsaKey = privateKey as RSAPrivateKey
  val nBytes =
    (ByteArray(256) + rsaKey.modulus.toByteArray()).let {
      it.copyOfRange(it.size - 256, it.size)
    }
  val dBytes =
    (ByteArray(256) + rsaKey.privateExponent.toByteArray()).let {
      it.copyOfRange(it.size - 256, it.size)
    }
  return nBytes + dBytes
}
````

Private key raw data bytes can be converted back to `java.security.PrivateKey` with
````kotlin
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.ECPrivateKeySpec
import java.security.spec.RSAPrivateKeySpec
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter

fun rebuildES256FromPrivateKeyRawBytes(bytes: ByteArray): PrivateKey {
  require(bytes.size == 32) { "ECDSA P-256 raw private key must be 32 bytes" }
  val s = BigInteger(1, bytes)

  val params =
    AlgorithmParameters.getInstance("EC", BouncyCastleProvider()).apply {
      init(java.security.spec.ECGenParameterSpec("secp256r1"))
    }
  val ecParameters = params.getParameterSpec(java.security.spec.ECParameterSpec::class.java)

  val keySpec = ECPrivateKeySpec(s, ecParameters)
  val keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider())

  return keyFactory.generatePrivate(keySpec)
}

fun rebuildEd25519FromPrivateKeyRawBytes(bytes: ByteArray): PrivateKey {
  require(bytes.size == 32) { "Ed25519 raw private key must be 32 bytes" }

  val privateKeyParams = Ed25519PrivateKeyParameters(bytes, 0)
  val privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams)

  return JcaPEMKeyConverter().setProvider(BouncyCastleProvider()).getPrivateKey(privateKeyInfo)
}

fun rebuildRS256FromPrivateKeyRawBytes(bytes: ByteArray): PrivateKey {
  require(bytes.size == 512) { "Buffer must be exactly 512 bytes" }
  val n = BigInteger(1, bytes.copyOfRange(0, 256))
  val d = BigInteger(1, bytes.copyOfRange(256, 512))

  val keySpec = RSAPrivateKeySpec(n, d)
  return KeyFactory.getInstance("RSA", BouncyCastleProvider()).generatePrivate(keySpec)
}
````
