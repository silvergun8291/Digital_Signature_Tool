fun getMode(): String {
    var mode: String

    while (true) {
        println("\n원하는 모드를 입력하세요.")
        println("Encrypt/Sign - S")
        println("Decrypt/Verify - V")
        println("Quit - Q")
        print("> ")

        mode = readln()

        if (mode == "S" || mode == "V" || mode == "Q") {
            break
        }
        else {
            println("잘못된 입력입니다.")
        }
    }

    return mode
}


fun sign(aes: AES, rsa: RSA, sha: SHA, msg: String): String {
    val enc: String = aes.encrypt(msg)
    val sig: String = rsa.encrypt(sha.sha512(enc))
    val digitalSig: String = enc + sig

    return digitalSig
}


fun verify(aes: AES, rsa: RSA, sha: SHA, digitalSignature: String): String {
    val length: Int = digitalSignature.length
    val index: Int = length - 344

    val enc: String = digitalSignature.substring(0, index)
    val sig: String = digitalSignature.substring(index)

    val hash1 = rsa.decrypt(sig)
    val hash2 = sha.sha512(enc)

    if (hash1 == hash2) {
        println("verify: authenticated user")
    }
    else {
        println("verify: unauthenticated user")
    }

    return aes.decrypt(enc)
}


fun clearConsole() {
    Thread.sleep(1000)
    print("\u001b[H\u001b[2J")
    System.out.flush()
}


fun main() {
    val aes = AES()
    val rsa = RSA()
    val sha = SHA()

    while(true) {
        when (getMode()) {
            "S" -> {
                println("\n메시지를 입력하세요.")
                print("> ")
                val msg: String = readln()

                val digitalSignature = sign(aes, rsa, sha, msg)
                println("Digital Signature : $digitalSignature")
            }

            "V" -> {
                println("\n디지털 서명을 입력하세요.")
                print("> ")
                val digitalSignature: String = readln()
                val msg: String = verify(aes, rsa, sha, digitalSignature)

                println("Message: $msg")
            }
            "Q" -> return
        }

        clearConsole()
    }
}