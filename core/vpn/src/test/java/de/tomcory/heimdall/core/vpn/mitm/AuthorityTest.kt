package de.tomcory.heimdall.core.vpn.mitm

import org.junit.Assert.*
import org.junit.Test
import java.io.File

/**
 * Regression tests for docs/vpn-mitm-audit.md PKT-06 (V-01): the MitM CA keystore password used
 * to be the hardcoded literal "changeit" (the well-known Java default cacerts password), which
 * gave the CA's private key no real protection. [Authority.getDefaultInstance] now generates a
 * random per-install password on first use and persists it next to the keystore.
 */
class AuthorityTest {

    @Test
    fun `getDefaultInstance no longer uses the hardcoded 'changeit' password`() {
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)
            assertFalse(
                "the keystore password must not be the old hardcoded literal",
                String(authority.password) == "changeit"
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `two separate installs get two different random passwords`() {
        val dirA = createTempDir()
        val dirB = createTempDir()
        try {
            val passwordA = String(Authority.getDefaultInstance(dirA).password)
            val passwordB = String(Authority.getDefaultInstance(dirB).password)

            assertNotEquals(
                "two separate keystore directories must not end up with the same generated password",
                passwordA,
                passwordB
            )
        } finally {
            dirA.deleteRecursively()
            dirB.deleteRecursively()
        }
    }

    @Test
    fun `the same install reuses its persisted password across calls`() {
        val dir = createTempDir()
        try {
            val first = String(Authority.getDefaultInstance(dir).password)
            val second = String(Authority.getDefaultInstance(dir).password)

            assertEquals(
                "re-loading the same keystore directory must return the same (persisted) password",
                first,
                second
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `the generated password is persisted to a file in the keystore directory`() {
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)
            val passwordFile = File(dir, "heimdallmitm.pwd")

            assertTrue("expected a persisted password file next to the keystore", passwordFile.exists())
            assertEquals(String(authority.password), passwordFile.readText().trim())
        } finally {
            dir.deleteRecursively()
        }
    }
}
