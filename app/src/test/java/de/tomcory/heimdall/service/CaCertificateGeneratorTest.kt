package de.tomcory.heimdall.service

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

class CaCertificateGeneratorTest {

    private lateinit var dir: File
    private lateinit var keyStoreDir: File
    private lateinit var exportDir: File
    private var vpnActive = false

    private val generator by lazy {
        CaCertificateGenerator(keyStoreDir, exportDir) { vpnActive }
    }

    @Before
    fun setUp() {
        dir = Files.createTempDirectory("ca-generator").toFile()
        keyStoreDir = File(dir, "keystore")
        exportDir = File(dir, "ca")
    }

    @After
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun generate(force: Boolean) = runBlocking { generator.generate(force) }

    @Test
    fun `a fresh install generates the CA and exports both files`() {
        val outcome = generate(force = false)

        assertTrue("expected Generated, got $outcome", outcome is CaCertificateGenerator.Outcome.Generated)
        val export = (outcome as CaCertificateGenerator.Outcome.Generated).export
        assertTrue(export.pemFile.exists())
        assertTrue(export.systemFile.exists())
        assertEquals(exportDir, export.systemFile.parentFile)
        assertEquals("${export.hash}.0", export.systemFile.name)
    }

    @Test
    fun `a second call reuses the existing CA`() {
        // both calls export to the same file, so read the first export before the second call
        val firstPem = (generate(force = false) as CaCertificateGenerator.Outcome.Generated).export.pemFile.readText()
        val second = generate(force = false)

        assertTrue("expected Reused, got $second", second is CaCertificateGenerator.Outcome.Reused)
        assertEquals(
            firstPem,
            (second as CaCertificateGenerator.Outcome.Reused).export.pemFile.readText()
        )
    }

    @Test
    fun `force regenerates the CA while the VPN is inactive`() {
        // both calls export to the same file, so read the first export before the second call
        val firstPem = (generate(force = false) as CaCertificateGenerator.Outcome.Generated).export.pemFile.readText()
        val second = generate(force = true)

        assertTrue("expected Generated, got $second", second is CaCertificateGenerator.Outcome.Generated)
        assertNotEquals(
            firstPem,
            (second as CaCertificateGenerator.Outcome.Generated).export.pemFile.readText()
        )
    }

    @Test
    fun `force is refused while the VPN is active and leaves the key store untouched`() {
        generate(force = false)
        val keyStoreFile = File(keyStoreDir, "heimdallmitm.p12")
        val before = keyStoreFile.readBytes()

        vpnActive = true
        val outcome = generate(force = true)

        assertEquals(CaCertificateGenerator.Outcome.RefusedVpnActive, outcome)
        assertTrue(before.contentEquals(keyStoreFile.readBytes()))
    }
}
