import java.security.MessageDigest
import kotlin.text.Charsets.UTF_8


class SHA {
    fun sha512(input: String): String {
        val bytes = input.toByteArray(UTF_8)
        val md = MessageDigest.getInstance("SHA-512")
        val digest = md.digest(bytes)
        return digest.fold("") { str, it -> str + "%02x".format(it) }
    }
}