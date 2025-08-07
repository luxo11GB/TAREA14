package com.example.seguridad_priv_a.security

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.*

data class ForensicEvidence(
    val id: String,
    val timestamp: Long,
    val event: String,
    val user: String,
    val metadata: Map<String, String>,
    val prevHash: String,
    var hash: String = ""
)

class ForensicManager(private val context: Context) {

    private val chainOfCustody = mutableListOf<ForensicEvidence>()
    private val dateFormatter = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())

    /**
     * Registra una evidencia en la cadena (Chain of Custody)
     */
    fun logEvidence(event: String, user: String, metadata: Map<String, String> = emptyMap()) {
        val prevHash = chainOfCustody.lastOrNull()?.hash ?: "GENESIS"
        val evidence = ForensicEvidence(
            id = UUID.randomUUID().toString(),
            timestamp = System.currentTimeMillis(),
            event = event,
            user = user,
            metadata = metadata,
            prevHash = prevHash
        )
        evidence.hash = calculateHash(evidence)
        chainOfCustody.add(evidence)
    }

    /**
     * Verifica la integridad de la cadena de custodia
     */
    fun verifyChainIntegrity(): Boolean {
        for (i in 1 until chainOfCustody.size) {
            val current = chainOfCustody[i]
            val prev = chainOfCustody[i - 1]
            if (current.prevHash != prev.hash || calculateHash(current) != current.hash) {
                return false
            }
        }
        return true
    }

    /**
     * Genera un reporte de compliance (GDPR / CCPA)
     */
    fun generateComplianceReport(): String {
        val report = JSONObject()
        report.put("reportDate", dateFormatter.format(Date()))
        report.put("totalEvents", chainOfCustody.size)
        report.put("chainValid", verifyChainIntegrity())
        report.put("regulation", "GDPR/CCPA")
        report.put("userDataAccesses", chainOfCustody.count { it.event.contains("ACCESS") })
        report.put("userDataDeletions", chainOfCustody.count { it.event.contains("DELETE") })

        return report.toString(4)
    }

    /**
     * Herramienta básica de investigación de incidentes
     */
    fun investigateIncident(keyword: String): List<ForensicEvidence> {
        return chainOfCustody.filter {
            it.event.contains(keyword, ignoreCase = true) ||
                    it.metadata.values.any { v -> v.contains(keyword, ignoreCase = true) }
        }
    }

    /**
     * Exporta la cadena completa en JSON
     */
    fun exportChain(): String {
        val jsonArray = org.json.JSONArray()
        for (evidence in chainOfCustody) {
            val json = JSONObject()
            json.put("id", evidence.id)
            json.put("timestamp", dateFormatter.format(Date(evidence.timestamp)))
            json.put("event", evidence.event)
            json.put("user", evidence.user)
            json.put("metadata", JSONObject(evidence.metadata))
            json.put("prevHash", evidence.prevHash)
            json.put("hash", evidence.hash)
            jsonArray.put(json)
        }
        return jsonArray.toString(4)
    }

    /**
     * Cálculo del hash SHA-256 para el log tamper-evident
     */
    private fun calculateHash(evidence: ForensicEvidence): String {
        val input = "${evidence.id}${evidence.timestamp}${evidence.event}${evidence.user}${evidence.prevHash}"
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }
}
