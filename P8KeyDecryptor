import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class P8KeyDecryptor {

    public static void main(String[] args) throws Exception {
        // Path to your encrypted RSA private key (like rsa_key.p8)
        String filePath = "rsa_key.p8";
        // The passphrase used to encrypt the key
        String passphrase = "123456";

        String pemContent = readFile(filePath);
        // Extract and parse the encrypted PEM
        EncryptedPemInfo pemInfo = parseEncryptedPem(pemContent);

        // We now have:
        // - pemInfo.algorithm (e.g. "AES-256-CBC")
        // - pemInfo.hexIv (the hex string from DEK-Info line)
        // - pemInfo.encryptedData (the base64-decoded encrypted key bytes)

        // Convert hex IV to bytes
        byte[] ivAndSalt = hexStringToBytes(pemInfo.hexIv);

        // For older OpenSSL-style encryption:
        // - First 8 bytes of ivAndSalt are the salt
        // - The entire ivAndSalt (16 bytes) is the IV for AES-256-CBC
        byte[] salt = Arrays.copyOfRange(ivAndSalt, 0, 8);
        byte[] iv = Arrays.copyOfRange(ivAndSalt, 0, 16);

        // Decrypt using AES/CBC with derived key
        byte[] decryptedKey = decrypt(pemInfo.encryptedData, passphrase, salt, iv);

        // Now 'decryptedKey' is the plaintext PKCS#1 RSA private key bytes.
        // You can print it with the appropriate PEM headers:
        String base64Key = Base64.getEncoder().encodeToString(decryptedKey);
        System.out.println("-----BEGIN RSA PRIVATE KEY-----");
        // Insert newlines every 64 chars for readability
        for (int i = 0; i < base64Key.length(); i += 64) {
            int end = Math.min(i + 64, base64Key.length());
            System.out.println(base64Key.substring(i, end));
        }
        System.out.println("-----END RSA PRIVATE KEY-----");
    }

    /**
     * Reads the entire file into a String.
     */
    private static String readFile(String filePath) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString().trim();
    }

    /**
     * Extracts the DEK-Info and encrypted data from the provided PEM content.
     */
    private static EncryptedPemInfo parseEncryptedPem(String pemContent) throws IOException {
        BufferedReader reader = new BufferedReader(new StringReader(pemContent));
        String line;
        String dekInfoLine = null;
        ArrayList<String> base64Lines = new ArrayList<>();
        boolean inKey = false;

        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.contains("-----BEGIN RSA PRIVATE KEY-----")) {
                inKey = true;
            } else if (line.contains("-----END RSA PRIVATE KEY-----")) {
                inKey = false;
                break;
            } else if (inKey) {
                if (line.startsWith("DEK-Info:")) {
                    dekInfoLine = line;
                } else if (!line.isEmpty() && !line.startsWith("Proc-Type:") && !line.startsWith("DEK-Info:")) {
                    base64Lines.add(line);
                }
            }
        }

        if (dekInfoLine == null) {
            throw new IllegalArgumentException("DEK-Info line not found; is this key actually encrypted?");
        }

        // DEK-Info line format: "DEK-Info: AES-256-CBC,<hex_iv>"
        // Example: DEK-Info: AES-256-CBC,004832D9748122DBB5F423A42BB1B111
        String[] parts = dekInfoLine.split(":", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid DEK-Info line format.");
        }
        String info = parts[1].trim();
        String[] algoAndHex = info.split(",", 2);
        if (algoAndHex.length != 2) {
            throw new IllegalArgumentException("Invalid DEK-Info line format, missing IV part.");
        }

        String algorithm = algoAndHex[0].trim();
        String hexIv = algoAndHex[1].trim();


        System.out.println(algorithm);
        System.out.println(hexIv);
        System.out.println(base64Lines);

        // Combine all base64 lines and decode
        String base64Data = String.join("", base64Lines);
        byte[] encryptedData = Base64.getDecoder().decode(base64Data);

        return new EncryptedPemInfo(algorithm, hexIv, encryptedData);
    }

    /**
     * Decrypts the encrypted key data using AES-256-CBC with OpenSSL-style key derivation.
     * @param encryptedData The encrypted key bytes
     * @param passphrase The password used for encryption
     * @param salt The first 8 bytes of the IV are used as salt
     * @param iv The 16-byte IV
     */
    private static byte[] decrypt(byte[] encryptedData, String passphrase, byte[] salt, byte[] iv) throws Exception {
        // Derive key and IV using OpenSSL's older MD5-based scheme
        KeyIV keyIV = deriveKeyAndIV(passphrase, salt, 32, 16);

        // We got a key and IV from derivation, but we must ensure we use the given 'iv' from the file
        // In OpenSSL encryption, the IV used for cipher is also the same 16 bytes from DEK-Info.
        // The derived IV should match, but we'll trust the DEK-Info IV here:
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keyIV.keySpec, ivSpec);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Derives the key and IV using an MD5-based scheme similar to older OpenSSL EVP_BytesToKey.
     */
    private static KeyIV deriveKeyAndIV(String passphrase, byte[] salt, int keyLen, int ivLen) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] passBytes = passphrase.getBytes(StandardCharsets.UTF_8);

        byte[] keyAndIv = new byte[keyLen + ivLen];
        byte[] prev = new byte[0];
        int offset = 0;
        while (offset < keyAndIv.length) {
            md.update(prev);
            md.update(passBytes);
            md.update(salt, 0, salt.length);
            prev = md.digest();
            System.arraycopy(prev, 0, keyAndIv, offset, prev.length);
            offset += prev.length;
            md.reset();
        }

        byte[] key = Arrays.copyOfRange(keyAndIv, 0, keyLen);
        byte[] iv = Arrays.copyOfRange(keyAndIv, keyLen, keyLen + ivLen);
        return new KeyIV(new SecretKeySpec(key, "AES"), iv);
    }

    /**
     * Converts a hex string to a byte array.
     */
    private static byte[] hexStringToBytes(String hex) {
        if ((hex.length() % 2) != 0)
            throw new IllegalArgumentException("Hex string must have even length");
        int len = hex.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            int index = i * 2;
            int val = Integer.parseInt(hex.substring(index, index + 2), 16);
            out[i] = (byte) val;
        }
        return out;
    }

    private static class EncryptedPemInfo {
        String algorithm;
        String hexIv;
        byte[] encryptedData;
        EncryptedPemInfo(String algorithm, String hexIv, byte[] encryptedData) {
            this.algorithm = algorithm;
            this.hexIv = hexIv;
            this.encryptedData = encryptedData;
        }
    }

    private static class KeyIV {
        SecretKeySpec keySpec;
        byte[] iv;
        KeyIV(SecretKeySpec keySpec, byte[] iv) {
            this.keySpec = keySpec;
            this.iv = iv;
        }
    }
}
