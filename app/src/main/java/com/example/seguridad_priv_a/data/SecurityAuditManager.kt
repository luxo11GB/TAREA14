package com.example.seguridad_priv_a

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.util.*

class SecurityAuditManager(private val context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("security_audit_prefs", Context.MODE_PRIVATE)

    private val accessAttempts = mutableListOf<Long>()
    private val logs = mutableListOf<JSONObject>()
    private var keyPair: KeyPair

    // Configuración de thresholds
    private val suspiciousThreshold = 5     // Máx 5 accesos
    private val timeWindowMs = 10_000L      // En 10 segundos
    private val rateLimitThreshold = 3      // Máx 3 operaciones sensibles
    private val rateLimitWindowMs = 15_000L // En 15 segundos

    private val sensitiveOps = mutableListOf<Long>()

    init {
        keyPair = generateKeyPair()
    }

    // ======================================================
    // 🔍 Registrar intentos de acceso
    // ======================================================
    fun registerAccess(tag: String, message: String) {
        val now = System.currentTimeMillis()
        accessAttempts.add(now)
        logs.add(JSONObject().apply {
            put("timestamp", Date(now).toString())
            put("tag", tag)
            put("message", message)
        })
        checkSuspiciousActivity()
    }

    // ======================================================
    // 🚦 Rate limiting
    // ======================================================
    fun registerSensitiveOperation(): Boolean {
        val now = System.currentTimeMillis()
        sensitiveOps.add(now)
        cleanOld(sensitiveOps, rateLimitWindowMs)

        return if (sensitiveOps.size > rateLimitThreshold) {
            generateAlert("Rate Limit Excedido", "Demasiadas operaciones sensibles en poco tiempo")
            false
        } else {
            true
        }
    }

    // ======================================================
    // ⚠️ Detección de actividad sospechosa
    // ======================================================
    private fun checkSuspiciousActivity() {
        cleanOld(accessAttempts, timeWindowMs)
        if (accessAttempts.size > suspiciousThreshold) {
            generateAlert("Actividad Sospechosa", "Múltiples intentos de acceso detectados")
        }
    }

    private fun cleanOld(list: MutableList<Long>, window: Long) {
        val cutoff = System.currentTimeMillis() - window
        list.removeIf { it < cutoff }
    }

    // ======================================================
    // 🚨 Generación de alertas
    // ======================================================
    private fun generateAlert(title: String, details: String) {
        val now = Date()
        val alert = JSONObject().apply {
            put("timestamp", now.toString())
            put("alert", title)
            put("details", details)
        }
        logs.add(alert)
        Log.w("SecurityAuditManager", "⚠️ ALERTA: $title - $details")
    }

    // ======================================================
    // 📤 Exportar logs en JSON firmado digitalmente
    // ======================================================
    fun exportSignedLogs(): JSONObject {
        val jsonLogs = JSONArray(logs)
        val logsObject = JSONObject().apply {
            put("exported_at", Date().toString())
            put("logs", jsonLogs)
        }

        val signature = signData(logsObject.toString().toByteArray())
        logsObject.put("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
        logsObject.put("public_key", Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP))

        return logsObject
    }

    // ======================================================
    // 🔑 Firma digital con RSA
    // ======================================================
    private fun generateKeyPair(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(2048)
        return keyGen.generateKeyPair()
    }

    private fun signData(data: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(keyPair.private)
        sig.update(data)
        return sig.sign()
    }

    fun verifySignature(data: ByteArray, signature: ByteArray, publicKey: PublicKey): Boolean {
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initVerify(publicKey)
        sig.update(data)
        return sig.verify(signature)
    }
}
