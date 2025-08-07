package com.example.seguridad_priv_a.security

import android.content.Context
import android.os.SystemClock
import android.util.Base64
import android.widget.Toast
import com.example.seguridad_priv_a.DataProtectionManager
import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class ZeroTrustManager(private val context: Context, private val dataManager: DataProtectionManager) {

    private var sessionToken: String? = null
    private var tokenExpiry: Long = 0
    private val secureRandom = SecureRandom()

    /**
     * Genera un token temporal para operaciones sensibles
     */
    fun generateSessionToken(): String {
        val randomBytes = ByteArray(32)
        secureRandom.nextBytes(randomBytes)
        val token = Base64.encodeToString(randomBytes, Base64.NO_WRAP)

        sessionToken = token
        tokenExpiry = SystemClock.elapsedRealtime() + (5 * 60 * 1000) // 5 minutos de validez

        dataManager.logAccess("ZERO_TRUST", "Token de sesión generado")
        return token
    }

    /**
     * Verifica si el token de sesión aún es válido
     */
    fun isSessionValid(token: String?): Boolean {
        val valid = token != null && token == sessionToken && SystemClock.elapsedRealtime() < tokenExpiry
        if (!valid) {
            dataManager.logAccess("ZERO_TRUST", "Token inválido o expirado")
        }
        return valid
    }

    /**
     * Valida operaciones sensibles bajo el principio de menor privilegio
     */
    fun validateSensitiveOperation(operation: String, token: String?): Boolean {
        if (!isSessionValid(token)) {
            Toast.makeText(context, "Sesión expirada o inválida", Toast.LENGTH_SHORT).show()
            return false
        }

        // Validación adicional (Zero Trust)
        val attestation = performIntegrityAttestation()
        return if (!attestation) {
            dataManager.logAccess("ZERO_TRUST", "Attestation fallida para $operation")
            false
        } else {
            dataManager.logAccess("ZERO_TRUST", "Operación $operation validada")
            true
        }
    }

    /**
     * Attestation de integridad de la aplicación
     * (Aquí simulamos, pero en producción usarías Play Integrity API o SafetyNet)
     */
    private fun performIntegrityAttestation(): Boolean {
        // Simulación: generar un HMAC como prueba de integridad
        val key = "ZeroTrustSecretKey".toByteArray()
        val message = "AppIntegrityCheck".toByteArray()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val hmac = mac.doFinal(message)
        val attestationResult = Base64.encodeToString(hmac, Base64.NO_WRAP)

        // Aquí podrías enviar el resultado a un servidor seguro para validación
        dataManager.logAccess("ZERO_TRUST", "Attestation generada: $attestationResult")
        return true
    }

    /**
     * Exporta estado actual en formato JSON
     */
    fun exportZeroTrustReport(): String {
        val report = JSONObject()
        report.put("tokenActive", sessionToken != null && SystemClock.elapsedRealtime() < tokenExpiry)
        report.put("tokenExpiry", tokenExpiry)
        report.put("lastLog", System.currentTimeMillis())

        return report.toString()
    }
}
