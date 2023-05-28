import java.security.*
import java.util.*
import javax.crypto.Cipher


class RSA {
    companion object {
        private val RSA_KEY_SIZE: Int = 2048
        private val CIPHER_ALGORITHM: String = "RSA/ECB/PKCS1Padding"
        private var publicKey: PublicKey? = null
        private var privateKey: PrivateKey? = null
    }

    init {
        val keyPair: KeyPair? = generateRSAKeyPair()
        publicKey = keyPair?.public
        privateKey = keyPair?.private
    }


    private fun generateRSAKeyPair(): KeyPair? { // RSA Key Pair 생성
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(RSA_KEY_SIZE) // 키 크기 설정

            return keyPairGenerator.generateKeyPair()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        }
        return null     // key pair를 생성하지 못하면 null 리턴
    }


    public fun encrypt(plainText: String): String {
        if (publicKey == null) {
            throw IllegalArgumentException("Public key is null.")
        }

        var cipherText: String = ""

        try {
            val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)

            val encrypted: ByteArray = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

            cipherText = Base64.getEncoder().encodeToString(encrypted)
        } catch (e: Exception) {
            e.printStackTrace()
        }

        return cipherText
    }


    public fun decrypt(cipherText: String): String {
        if (privateKey == null) {
            throw IllegalArgumentException("Private key is null.")
        }

        var plainText: String = ""

        try {
            val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)

            val decoded: ByteArray = Base64.getDecoder().decode(cipherText)
            val decrypted: ByteArray = cipher.doFinal(decoded)

            plainText = String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            e.printStackTrace()
        }

        return plainText
    }
}