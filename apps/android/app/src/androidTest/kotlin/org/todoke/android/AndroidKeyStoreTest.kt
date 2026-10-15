// The storage key's wrapping in the Android Keystore: a key stored once
// comes back and is never replaced; a damaged blob, a gone Keystore key,
// or another profile's blob fails with a reason (never as "unlock first",
// which would only ask again); protection is reported from where the key
// really is. Ungated: the emulator has no lock screen.

package org.todoke.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore as JavaKeyStore
import java.security.SecureRandom
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.todoke.android.core.AndroidKeyStore
import org.todoke.ffi.KeyProtection
import org.todoke.ffi.KeyStoreError

@RunWith(AndroidJUnit4::class)
class AndroidKeyStoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val profiles = mutableListOf<String>()

    private fun profile(): String =
        ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }.also { profiles += it }

    private fun blob(profile: String) = File(context.noBackupFilesDir, "keys/$profile.key")

    private fun key(fill: Int) = ByteArray(32) { (it + fill).toByte() }

    @After
    fun cleanUp() {
        val keystore = JavaKeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (profile in profiles) {
            keystore.deleteEntry("todoke-storage-$profile")
            blob(profile).delete()
        }
    }

    @Test
    fun aStoredKeyComesBackAndIsNeverReplaced() {
        val store = AndroidKeyStore(context, gated = false)
        val profile = profile()
        assertNull(store.load(profile))
        val stored = key(1)
        store.store(profile, stored.copyOf())
        assertArrayEquals(stored, store.load(profile))
        assertEquals(1 + 12 + 32 + 16, blob(profile).length().toInt())
        assertThrows(KeyStoreError.AlreadyExists::class.java) { store.store(profile, key(2)) }
        assertArrayEquals(stored, store.load(profile))
    }

    @Test
    fun theKeyGivenToStoreIsWiped() {
        val given = key(3)
        AndroidKeyStore(context, gated = false).store(profile(), given)
        assertArrayEquals(ByteArray(32), given)
    }

    @Test
    fun aDamagedBlobFailsWithAReason() {
        val store = AndroidKeyStore(context, gated = false)
        val profile = profile()
        store.store(profile, key(4))
        val bytes = blob(profile).readBytes().also { it[20] = (it[20].toInt() xor 1).toByte() }
        blob(profile).writeBytes(bytes)
        assertThrows(KeyStoreError.Unavailable::class.java) { store.load(profile) }
        assertFalse(store.refused)
        assertNotNull(store.problem)

        blob(profile).writeBytes(bytes.copyOf(10))
        assertThrows(KeyStoreError.Unavailable::class.java) { store.load(profile) }
        assertFalse(store.refused)
    }

    @Test
    fun aGoneKeystoreKeyFailsWithAReason() {
        val store = AndroidKeyStore(context, gated = false)
        val profile = profile()
        store.store(profile, key(5))
        JavaKeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry("todoke-storage-$profile")
        assertThrows(KeyStoreError.Unavailable::class.java) { store.load(profile) }
        assertFalse(store.refused)
        assertNotNull(store.problem)
    }

    @Test
    fun anotherProfilesBlobDoesNotOpen() {
        val store = AndroidKeyStore(context, gated = false)
        val (first, second) = profile() to profile()
        store.store(first, key(6))
        store.store(second, key(7))
        // The second profile's key with the first's blob: wrong key and
        // wrong associated data.
        blob(second).writeBytes(blob(first).readBytes())
        assertThrows(KeyStoreError.Unavailable::class.java) { store.load(second) }
    }

    @Test
    fun protectionIsWhereTheKeyIs() {
        val store = AndroidKeyStore(context, gated = false)
        // Nothing known yet: never claims StrongBox.
        assertEquals(KeyProtection.TEE, store.protection())
        val profile = profile()
        store.store(profile, key(8))
        val expected = if (store.inStrongBox(profile) == true) KeyProtection.STRONG_BOX else KeyProtection.TEE
        assertEquals(expected, store.protection())
    }
}
