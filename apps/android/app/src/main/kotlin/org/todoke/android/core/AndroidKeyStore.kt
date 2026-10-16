// The core's storage key, kept wrapped by a non-exportable AES-256-GCM key
// in the Android Keystore: in StrongBox where the device has one, else in
// the TEE. Only the wrapped bytes are on disk, in no-backup storage (a
// restored backup must never bring back an old key, PROTOCOL §16 O3).
//
// With `gated`, the Keystore key may only be used for 30 seconds after the
// user unlocks with a strong biometric or the device credential: the app
// asks (BiometricPrompt) right before it starts the core. New fingerprints
// do not invalidate the key, so enrolling one never locks a profile out;
// removing the screen lock does invalidate it (Android's rule for keys that
// need authentication), and the app then says the key is gone.

package org.todoke.android.core

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.security.KeyStore as JavaKeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import org.todoke.ffi.KeyProtection
import org.todoke.ffi.KeyStore
import org.todoke.ffi.KeyStoreError

class AndroidKeyStore(private val context: Context, private val gated: Boolean) : KeyStore {
    private val dir = File(context.noBackupFilesDir, "keys")

    /** The profile last loaded or stored, for [protection]. */
    @Volatile
    private var profile: String? = null

    /** Whether the last failure was the user not having unlocked (asking
     * again helps), and what the last failure was, for people. */
    @Volatile
    var refused = false
        private set

    @Volatile
    var problem: String? = null
        private set

    private fun fail(error: KeyStoreError, refusal: Boolean, why: String): Nothing {
        refused = refusal
        problem = why
        throw error
    }

    private fun alias(profile: String) = "todoke-storage-$profile"

    private fun keystore(): JavaKeyStore = JavaKeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun strongBoxAvailable(): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /** StrongBox only when the profile's key is known to be there (the
     * generator falls back to the TEE). */
    override fun protection(): KeyProtection =
        if (profile?.let { runCatching { inStrongBox(it) }.getOrNull() } == true) KeyProtection.STRONG_BOX else KeyProtection.TEE

    override fun load(profile: String): ByteArray? {
        this.profile = profile
        refused = false
        val file = File(dir, "$profile.key")
        if (!file.exists()) return null
        val key = keystore().getKey(alias(profile), null) as? SecretKey
            ?: fail(KeyStoreError.Unavailable("the wrapping key is gone"), false, GONE)
        val blob = file.readBytes()
        if (blob.size != BLOB_LEN || blob[0] != VERSION) {
            fail(KeyStoreError.Unavailable("the stored key is damaged"), false, DAMAGED)
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, blob, 1, IV_LEN))
            cipher.updateAAD(profile.toByteArray())
            cipher.doFinal(blob, 1 + IV_LEN, blob.size - 1 - IV_LEN)
        } catch (error: UserNotAuthenticatedException) {
            fail(KeyStoreError.Refused("unlock to open todoke"), true, LOCKED)
        } catch (error: KeyPermanentlyInvalidatedException) {
            fail(KeyStoreError.Unavailable("the wrapping key was invalidated"), false, INVALIDATED)
        } catch (error: java.security.GeneralSecurityException) {
            fail(KeyStoreError.Unavailable("the stored key could not be opened"), false, DAMAGED)
        }
    }

    override fun store(profile: String, key: ByteArray) {
        this.profile = profile
        refused = false
        try {
            val file = File(dir, "$profile.key")
            if (file.exists()) throw KeyStoreError.AlreadyExists
            dir.mkdirs()
            val wrapping = generate(alias(profile))
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, wrapping)
            cipher.updateAAD(profile.toByteArray())
            val sealed = cipher.doFinal(key)
            val iv = cipher.iv
            check(iv.size == IV_LEN && sealed.size == KEY_LEN + TAG_BITS / 8)
            // Written aside and renamed into place, so never torn, then the
            // directory synced. The core stores a profile's key once, holding
            // the profile's lock, so nothing else writes this name; the
            // check above refuses one stored before.
            val temp = File(dir, "$profile.key.tmp")
            temp.outputStream().use { out ->
                out.write(byteArrayOf(VERSION))
                out.write(iv)
                out.write(sealed)
                out.fd.sync()
            }
            if (!temp.renameTo(file) || file.length() != BLOB_LEN.toLong()) {
                temp.delete()
                fail(KeyStoreError.Unavailable("the key could not be stored"), false, NOT_STORED)
            }
            syncDir()
        } catch (error: UserNotAuthenticatedException) {
            fail(KeyStoreError.Refused("unlock to set up todoke"), true, LOCKED)
        } catch (error: java.security.GeneralSecurityException) {
            fail(KeyStoreError.Unavailable("the key could not be stored"), false, NOT_STORED)
        } catch (error: ErrnoException) {
            fail(KeyStoreError.Unavailable("the key could not be stored"), false, NOT_STORED)
        } finally {
            key.fill(0)
        }
    }

    private fun syncDir() {
        val fd = Os.open(dir.path, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(fd)
        } finally {
            Os.close(fd)
        }
    }

    /** The wrapping key for `alias`, made in StrongBox when there is one. */
    private fun generate(alias: String): SecretKey {
        keystore().getKey(alias, null)?.let { return it as SecretKey }
        val strongBox = strongBoxAvailable()
        return try {
            generate(alias, strongBox)
        } catch (error: StrongBoxUnavailableException) {
            generate(alias, false)
        }
    }

    private fun generate(alias: String, strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
        if (strongBox) spec.setIsStrongBoxBacked(true)
        if (gated) {
            spec.setUserAuthenticationRequired(true)
            spec.setUserAuthenticationParameters(
                UNLOCK_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            spec.setInvalidatedByBiometricEnrollment(false)
        }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).run {
            init(spec.build())
            generateKey()
        }
    }

    /** Whether the wrapping key of `profile` is in StrongBox. */
    fun inStrongBox(profile: String): Boolean? {
        val key = keystore().getKey(alias(profile), null) as? SecretKey ?: return null
        val info = SecretKeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
    }

    private companion object {
        // Why the key cannot be used, for people.
        const val LOCKED = "Unlock to open todoke."
        const val GONE = "todoke's key is gone from this device's key store, so its data cannot be opened."
        const val DAMAGED = "todoke's stored key is damaged, so its data cannot be opened."
        const val INVALIDATED = "todoke's key was erased when the screen lock was removed, so its data cannot be opened."
        const val NOT_STORED = "todoke could not store its key."

        const val PROVIDER = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val VERSION: Byte = 1
        const val IV_LEN = 12
        const val KEY_LEN = 32
        const val TAG_BITS = 128
        const val BLOB_LEN = 1 + IV_LEN + KEY_LEN + TAG_BITS / 8
        const val UNLOCK_SECONDS = 30
    }
}
