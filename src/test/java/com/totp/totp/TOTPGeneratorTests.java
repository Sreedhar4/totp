package com.totp.totp;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

public class TOTPGeneratorTests {
    @Test
    void testGenerateSecret() {
        String secret = new TOTPGenerator().generateSecret();
        assertNotNull(secret);
    }
}
