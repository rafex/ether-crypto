package dev.rafex.ether.crypto.password;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

final class PasswordHasherPBKDF2Test {

    @Test
    void shouldHashAndVerifyPassword() {
        final var hasher = new PasswordHasherPBKDF2(32);
        final var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        final var result = hasher.hash("secret-123".toCharArray(), salt, 120_000);

        assertEquals(120_000, result.iterations());
        assertArrayEquals(salt, result.salt());
        assertEquals(32, result.hash().length);
        assertTrue(hasher.verify("secret-123".toCharArray(), result.salt(), result.iterations(), result.hash()));
    }

    @Test
    void shouldRejectWrongPassword() {
        final var hasher = new PasswordHasherPBKDF2(32);
        final var salt = new byte[] { 9, 8, 7, 6, 5, 4, 3, 2 };
        final var result = hasher.hash("secret-123".toCharArray(), salt, 120_000);

        assertFalse(hasher.verify("wrong-password".toCharArray(), result.salt(), result.iterations(), result.hash()));
    }

    @Test
    void shouldReturnFalseForInvalidVerifyInput() {
        final var hasher = new PasswordHasherPBKDF2(32);

        assertFalse(hasher.verify(null, new byte[] { 1 }, 1, new byte[] { 1 }));
        assertFalse(hasher.verify("secret".toCharArray(), null, 1, new byte[] { 1 }));
        assertFalse(hasher.verify("secret".toCharArray(), new byte[] { 1 }, 0, new byte[] { 1 }));
        assertFalse(hasher.verify("secret".toCharArray(), new byte[] { 1 }, 1, null));
    }

    @Test
    void shouldRejectInvalidConstructionAndHashArguments() {
        assertThrows(IllegalArgumentException.class, () -> new PasswordHasherPBKDF2(15));

        final var hasher = new PasswordHasherPBKDF2(32);
        assertThrows(IllegalArgumentException.class, () -> hasher.hash(null, new byte[] { 1 }, 1));
        assertThrows(IllegalArgumentException.class, () -> hasher.hash("secret".toCharArray(), null, 1));
        assertThrows(IllegalArgumentException.class, () -> hasher.hash("secret".toCharArray(), new byte[0], 1));
        assertThrows(IllegalArgumentException.class, () -> hasher.hash("secret".toCharArray(), new byte[] { 1 }, 0));
    }

    @Test
    void hashResultShouldBeDefensivelyCopied() {
        final var hasher = new PasswordHasherPBKDF2(32);
        final var salt = new byte[] { 1, 2, 3, 4 };

        final var result = hasher.hash("secret".toCharArray(), salt, 10_000);
        final var hashCopy = result.hash();
        final var saltCopy = result.salt();

        hashCopy[0] = (byte) 0x7F;
        saltCopy[0] = (byte) 0x7F;

        assertFalse(hashCopy[0] == result.hash()[0]);
        assertFalse(saltCopy[0] == result.salt()[0]);
    }
}
