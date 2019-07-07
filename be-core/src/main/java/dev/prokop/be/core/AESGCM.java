package dev.prokop.be.core;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Bart Prokop
 */
public final class AESGCM {

    private static final SecureRandom SECURE_RANDOM = getSecureRandom();
    private static final Base64.Encoder BASE64URL = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder BASE64DEC = Base64.getDecoder();

    /**
     * A Tuple specific to AES GCM encryption mode.
     */
    public static final class Tuple {

        public final byte[] iv;
        public final byte[] cipherText;
        public final byte[] authTag;

        public Tuple(byte[] iv, byte[] cipherText, byte[] authTag) {
            this.iv = iv;
            this.cipherText = cipherText;
            this.authTag = authTag;
        }

        public static Tuple parse(String encrypted) {
            String[] parts = encrypted.split("\\.");
            final byte[] iv = BASE64DEC.decode(parts[0]);
            final byte[] cipherText = BASE64DEC.decode(parts[1]);
            final byte[] authTag = BASE64DEC.decode(parts[2]);
            return new Tuple(iv, cipherText, authTag);
        }

        @Override
        public String toString() {
            final StringBuilder retVal = new StringBuilder();
            retVal.append(BASE64URL.encodeToString(iv));
            retVal.append('.');
            retVal.append(BASE64URL.encodeToString(cipherText));
            retVal.append('.');
            retVal.append(BASE64URL.encodeToString(authTag));
            return retVal.toString();
        }

    }

    public static Tuple encrypt(final byte[] key, final byte[] plainText, final byte[] aad) {
        final SecretKey secretKey = validateKey(key);
        final byte[] iv = new byte[12];
        SECURE_RANDOM.nextBytes(iv);

        try {
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            cipher.updateAAD(aad);
            final byte[] encrypted = cipher.doFinal(plainText);
            final byte[] cipherText = new byte[encrypted.length - 128 / 8];
            final byte[] authTag = new byte[128 / 8];
            System.arraycopy(encrypted, 0, cipherText, 0, cipherText.length);
            System.arraycopy(encrypted, cipherText.length, authTag, 0, authTag.length);
            return new Tuple(iv, cipherText, authTag);
        } catch (GeneralSecurityException gse) {
            throw new RuntimeException(gse);
        }
    }

    public static byte[] decrypt(
            byte[] key,
            Tuple tuple,
            byte[] aad) {
        final SecretKey secretKey = validateKey(key);
        try {
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final GCMParameterSpec parameterSpec = new GCMParameterSpec(128, tuple.iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
            cipher.updateAAD(aad);
            final byte[] encrypted = new byte[tuple.cipherText.length + tuple.authTag.length];
            System.arraycopy(tuple.cipherText, 0, encrypted, 0, tuple.cipherText.length);
            System.arraycopy(tuple.authTag, 0, encrypted, tuple.cipherText.length, tuple.authTag.length);
            return cipher.doFinal(encrypted);
        } catch (GeneralSecurityException gse) {
            throw new RuntimeException(gse);
        }
    }

    private static SecretKey validateKey(byte[] key) {
        if (key.length != 256 / 8) {
            throw new IllegalArgumentException("Key should always be 256 bits.");
        }
        return new SecretKeySpec(key, "AES");
    }

    private static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException nsae) {
            throw new InternalError(nsae);
        }
    }

}
