package dev.rafex.ether.crypto.password;

import java.security.MessageDigest;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Arrays;

/**
 * PBKDF2-HMAC-SHA256 password hasher ported from Kiwi and HouseDB.
 */
public final class PasswordHasherPBKDF2 implements PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    private final int derivedKeyBytes;

    public PasswordHasherPBKDF2(final int derivedKeyBytes) {
        if (derivedKeyBytes < 16) {
            throw new IllegalArgumentException("derivedKeyBytes demasiado pequeño");
        }
        this.derivedKeyBytes = derivedKeyBytes;
    }

    @Override
    public boolean verify(final char[] password, final byte[] salt, final int iterations, final byte[] expectedHash) {
        if (password == null || salt == null || expectedHash == null || iterations <= 0) {
            return false;
        }

        final var derivedKey = derive(password, salt, iterations, expectedHash.length);
        try {
            return MessageDigest.isEqual(derivedKey, expectedHash);
        } finally {
            Arrays.fill(derivedKey, (byte) 0);
        }
    }

    @Override
    public PasswordHash hash(final char[] password, final byte[] salt, final int iterations) {
        if (password == null) {
            throw new IllegalArgumentException("password no puede ser null");
        }
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("salt no puede ser null o vacio");
        }
        if (iterations <= 0) {
            throw new IllegalArgumentException("iterations debe ser mayor que cero");
        }

        final var derivedKey = derive(password, salt, iterations, derivedKeyBytes);
        return new PasswordHash(derivedKey, salt, iterations);
    }

    private static byte[] derive(final char[] password, final byte[] salt, final int iterations,
            final int outLenBytes) {
        try {
            final var spec = new PBEKeySpec(password, salt, iterations, outLenBytes * 8);
            final var secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            return secretKeyFactory.generateSecret(spec).getEncoded();
        } catch (final Exception e) {
            throw new IllegalStateException("PBKDF2 derivation failed", e);
        }
    }
}
