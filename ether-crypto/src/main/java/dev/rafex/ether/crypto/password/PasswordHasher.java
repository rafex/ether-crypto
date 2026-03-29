package dev.rafex.ether.crypto.password;

/**
 * Contract for password hashing and verification.
 */
public interface PasswordHasher {

    /**
     * Hashes a password using the specified salt and iterations.
     *
     * @param password  The password to hash.
     * @param salt      The random salt bytes.
     * @param iterations The number of PBKDF2 iterations.
     * @return The resulting {@code PasswordHash}.
     */
    PasswordHash hash(char[] password, byte[] salt, int iterations);

    /**
     * Verifies a password against an expected hash.
     *
     * @param password      The password to verify.
     * @param salt          The random salt bytes.
     * @param iterations    The number of PBKDF2 iterations.
     * @param expectedHash  The expected hash bytes.
     * @return {@code true} if the password matches the expected hash, {@code false} otherwise.
     */
    boolean verify(char[] password, byte[] salt, int iterations, byte[] expectedHash);
}
