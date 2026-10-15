// The core's storage key, kept wrapped by a non-exportable AES-256-GCM key
// in the Android Keystore: in StrongBox where the device has one, else in
// the TEE. Only the wrapped bytes are on disk, in no-backup storage (a
// restored backup must never bring back an old key, PROTOCOL §16 O3).
//
// With `gated`, the Keystore key may only be used for 30 seconds after the
// user unlocks with a strong biometric or the device credential: the app
// asks (BiometricPrompt) right before it starts the core. New fingerprints
// do not invalidate the key, so enrolling one never locks a profile out.

package org.todoke.android.core

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
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

    private fun alias(profile: String) = "todoke-storage-$profile"

    private fun keystore(): JavaKeyStore = JavaKeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun strongBoxAvailable(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    override fun protection(): KeyProtection = if (strongBoxAvailable()) KeyProtection.STRONG_BOX else KeyProtection.TEE

    override fun load(profile: String): ByteArray? {
        val file = File(dir, "$profile.key")
        if (!file.exists()) return null
        val key = keystore().getKey(alias(profile), null) as? SecretKey
            ?: throw KeyStoreError.Unavailable("the wrapping key is gone")
        val blob = file.readBytes()
        if (blob.size != BLOB_LEN || blob[0] != VERSION) throw KeyStoreError.Unavailable("the stored key is damaged")
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, blob, 1, IV_LEN))
            cipher.updateAAD(profile.toByteArray())
            cipher.doFinal(blob, 1 + IV_LEN, blob.size - 1 - IV_LEN)
        } catch (error: android.security.keystore.UserNotAuthenticatedException) {
            throw KeyStoreError.Refused("unlock to open todoke")
        } catch (error: java.security.GeneralSecurityException) {
            throw KeyStoreError.Unavailable("the stored key could not be opened")
        }
    }

    override fun store(profile: String, key: ByteArray) {
        val file = File(dir, "$profile.key")
        if (file.exists()) throw KeyStoreError.AlreadyExists
        dir.mkdirs()
        val wrapping = generate(alias(profile))
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, wrapping)
            cipher.updateAAD(profile.toByteArray())
            val sealed = cipher.doFinal(key)
            val iv = cipher.iv
            check(iv.size == IV_LEN && sealed.size == KEY_LEN + TAG_BITS / 8)
            val temp = File(dir, "$profile.key.tmp")
            temp.outputStream().use { out ->
                out.write(byteArrayOf(VERSION))
                out.write(iv)
                out.write(sealed)
                out.fd.sync()
            }
            // Never replace: a key stored once stays the profile's.
            if (!temp.renameTo(file) || file.length() != BLOB_LEN.toLong()) {
                temp.delete()
                throw KeyStoreError.Unavailable("the key could not be stored")
            }
        } catch (error: android.security.keystore.UserNotAuthenticatedException) {
            throw KeyStoreError.Refused("unlock to set up todoke")
        } catch (error: java.security.GeneralSecurityException) {
            throw KeyStoreError.Unavailable("the key could not be stored")
        } finally {
            key.fill(0)
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
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) spec.setIsStrongBoxBacked(true)
        if (gated) {
            spec.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                spec.setUserAuthenticationParameters(
                    UNLOCK_SECONDS,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                spec.setUserAuthenticationValidityDurationSeconds(UNLOCK_SECONDS)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) spec.setInvalidatedByBiometricEnrollment(false)
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
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else {
            null
        }
    }

    private companion object {
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
