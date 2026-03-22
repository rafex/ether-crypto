package dev.rafex.ether.crypto.password;

import java.util.Arrays;

/**
 * Immutable password hash material.
 */
public record PasswordHash(byte[] hash, byte[] salt, int iterations) {

    public PasswordHash {
        hash = Arrays.copyOf(hash, hash.length);
        salt = Arrays.copyOf(salt, salt.length);
    }

    @Override
    public byte[] hash() {
        return Arrays.copyOf(hash, hash.length);
    }

    @Override
    public byte[] salt() {
        return Arrays.copyOf(salt, salt.length);
    }
}
