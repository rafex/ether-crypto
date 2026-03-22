package dev.rafex.ether.crypto.password;

/**
 * Contract for password hashing and verification.
 */
public interface PasswordHasher {

    PasswordHash hash(char[] password, byte[] salt, int iterations);

    boolean verify(char[] password, byte[] salt, int iterations, byte[] expectedHash);
}
