package dev.rafex.ether.crypto.password;

import java.util.Arrays;

/**
 * Immutable password hash material.
 *
 * @param hash         The derived key bytes.
 * @param salt         The random salt bytes.
 * @param iterations   The number of PBKDF2 iterations.
 */
public record PasswordHash(byte[] hash, byte[] salt, int iterations) {

    /**
     * Constructs a new {@code PasswordHash} and defensively copies the input arrays.
     */
    public PasswordHash {
        hash = Arrays.copyOf(hash, hash.length);
        salt = Arrays.copyOf(salt, salt.length);
    }

    /**
     * Returns a defensive copy of the hash bytes.
     *
     * @return A copy of the derived key bytes.
     */
    @Override
    public byte[] hash() {
        return Arrays.copyOf(hash, hash.length);
    }

    /**
     * Returns a defensive copy of the salt bytes.
     *
     * @return A copy of the random salt bytes.
     */
    @Override
    public byte[] salt() {
        return Arrays.copyOf(salt, salt.length);
    }
}
