package com.example.seguridad_priv_a

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import java.nio.charset.Charset
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class DataProtectionManager(private val context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences("data_protection_prefs", Context.MODE_PRIVATE)

    // Constantes
    private val AES_MODE = "AES/GCM/NoPadding"
    private val HMAC_ALGO = "HmacSHA256"
    private val KEY_SIZE = 256
    private val ITERATIONS = 10000
    private val IV_SIZE = 12
    private val TAG_SIZE = 128
    private val ROTATION_INTERVAL_DAYS = 30

    // Claves
    private var masterKey: SecretKey
    private var userSalt: ByteArray

    init {
        userSalt = getOrCreateSalt()
        masterKey = deriveKey("default_password", userSalt)
        rotateEncryptionKey() // Forzar verificación de rotación al iniciar
    }

    // ======================================================
    // 🔑 Rotación automática de claves maestras cada 30 días
    // ======================================================
    fun rotateEncryptionKey(): Boolean {
        val lastRotation = prefs.getLong("last_key_rotation", 0L)
        val now = System.currentTimeMillis()
        val daysElapsed = (now - lastRotation) / (1000 * 60 * 60 * 24)

        return if (daysElapsed >= ROTATION_INTERVAL_DAYS) {
            masterKey = deriveKey(UUID.randomUUID().toString(), userSalt)
            prefs.edit().putLong("last_key_rotation", now).apply()
            true
        } else {
            false
        }
    }

    // ======================================================
    // 🔑 Derivación de clave con PBKDF2 y salt único por usuario
    // ======================================================
    private fun deriveKey(password: String, salt: ByteArray): SecretKey {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE)
        val secret = factory.generateSecret(spec)
        return SecretKeySpec(secret.encoded, "AES")
    }

    private fun getOrCreateSalt(): ByteArray {
        val savedSalt = prefs.getString("user_salt", null)
        return if (savedSalt != null) {
            Base64.decode(savedSalt, Base64.DEFAULT)
        } else {
            val salt = ByteArray(16)
            SecureRandom().nextBytes(salt)
            prefs.edit().putString("user_salt", Base64.encodeToString(salt, Base64.DEFAULT)).apply()
            salt
        }
    }

    // ======================================================
    // 🔒 Encriptar datos con AES + HMAC para integridad
    // ======================================================
    fun encryptData(data: String): String {
        val cipher = Cipher.getInstance(AES_MODE)
        val iv = ByteArray(IV_SIZE).apply { SecureRandom().nextBytes(this) }
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, GCMParameterSpec(TAG_SIZE, iv))
        val cipherText = cipher.doFinal(data.toByteArray(Charset.forName("UTF-8")))

        val hmac = generateHmac(cipherText)

        val combined = iv + cipherText + hmac
        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    fun decryptData(encrypted: String): String? {
        try {
            val combined = Base64.decode(encrypted, Base64.DEFAULT)
            val iv = combined.copyOfRange(0, IV_SIZE)
            val cipherText = combined.copyOfRange(IV_SIZE, combined.size - 32) // último 32 bytes = HMAC
            val receivedHmac = combined.copyOfRange(combined.size - 32, combined.size)

            if (!verifyDataIntegrity(cipherText, receivedHmac)) {
                return null
            }

            val cipher = Cipher.getInstance(AES_MODE)
            cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(TAG_SIZE, iv))
            val plainText = cipher.doFinal(cipherText)
            return String(plainText, Charset.forName("UTF-8"))
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    fun anonymizeData(input: String?): String {
        if (input.isNullOrEmpty()) return "N/A"
        return if (input.length > 3) {
            input.take(3) + "*".repeat(input.length - 3)
        } else {
            "*".repeat(input.length)
        }
    }

    // ======================================================
    // ✅ Verificación de Integridad con HMAC
    // ======================================================
    private fun generateHmac(data: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGO)
        mac.init(masterKey)
        return mac.doFinal(data)
    }
    fun initialize() {
        // Aquí podrías cargar claves, verificar integridad, o configurar rotación
        logAccess("SECURITY_INIT", "DataProtectionManager inicializado")

        // Ejemplo: revisar rotación de clave al inicio
        rotateEncryptionKey()
    }


    fun verifyDataIntegrity(data: ByteArray, receivedHmac: ByteArray): Boolean {
        val calculatedHmac = generateHmac(data)
        return MessageDigest.isEqual(calculatedHmac, receivedHmac)
    }

    // ======================================================
    // 🔐 Funciones de acceso público
    // ======================================================
    fun getDataProtectionInfo(): Map<String, String> {
        val lastRotation = Date(prefs.getLong("last_key_rotation", 0L))
        return mapOf(
            "Algoritmo" to "AES-256-GCM + HMAC-SHA256",
            "Última Rotación de Clave" to lastRotation.toString(),
            "Salt Usuario" to Base64.encodeToString(userSalt, Base64.NO_WRAP)
        )
    }

    fun clearAllData() {
        prefs.edit().clear().apply()
    }

    fun logAccess(tag: String, message: String) {
        val logs = prefs.getStringSet("access_logs", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        logs.add("[${Date()}] $tag: $message")
        prefs.edit().putStringSet("access_logs", logs).apply()
    }

    fun getAccessLogs(): List<String> {
        return prefs.getStringSet("access_logs", emptySet())?.toList() ?: emptyList()
    }

    fun storeSecureData(key: String, value: String) {
        val encrypted = encryptData(value)
        prefs.edit().putString(key, encrypted).apply()
    }

    fun getSecureData(key: String): String? {
        val encrypted = prefs.getString(key, null)
        return encrypted?.let { decryptData(it) }
    }
}
