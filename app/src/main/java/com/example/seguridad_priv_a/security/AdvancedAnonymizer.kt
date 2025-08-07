package com.example.seguridad_priv_a.security

import kotlin.math.ln
import kotlin.math.sqrt
import kotlin.random.Random

// Modelo de datos personales
data class PersonalData(
    val id: String,
    val name: String,
    val age: Int,
    val gender: String,
    val city: String,
    val sensitiveAttribute: String
)

// Datos anonimizados
data class AnonymizedData(
    val id: String,
    val quasiIdentifiers: Map<String, String>,
    val sensitiveAttribute: String
)

// Datos numéricos para differential privacy
data class NumericData(
    val label: String,
    val value: Double
)

// Políticas de enmascaramiento
enum class MaskingPolicy {
    MASK_NAME,
    MASK_PHONE,
    MASK_EMAIL,
    MASK_GENERIC
}

class AdvancedAnonymizer {

    /**
     * Anonimización usando K-Anonymity con validación de L-Diversity
     */
    fun anonymizeWithKAnonymity(
        data: List<PersonalData>,
        k: Int,
        l: Int = 1
    ): List<AnonymizedData> {
        if (data.isEmpty()) return emptyList()

        // Agrupar por edad y ciudad como quasi-identificadores
        val grouped = data.groupBy { Pair(it.age / 10, it.city) } // Agrupa por rangos de 10 años + ciudad

        val anonymized = mutableListOf<AnonymizedData>()
        for ((_, group) in grouped) {
            if (group.size >= k) {
                // Verificar L-diversity en sensitiveAttribute
                val distinctSensitive = group.map { it.sensitiveAttribute }.toSet()
                if (distinctSensitive.size >= l) {
                    group.forEach {
                        anonymized.add(
                            AnonymizedData(
                                id = it.id,
                                quasiIdentifiers = mapOf(
                                    "ageRange" to "${(it.age / 10) * 10}-${(it.age / 10) * 10 + 9}",
                                    "city" to it.city
                                ),
                                sensitiveAttribute = "Anonimizado"
                            )
                        )
                    }
                }
            }
        }
        return anonymized
    }

    /**
     * Aplica Differential Privacy a un valor numérico usando Laplace Mechanism
     */
    fun applyDifferentialPrivacy(data: NumericData, epsilon: Double): NumericData {
        val sensitivity = 1.0
        val scale = sensitivity / epsilon
        val noise = laplaceNoise(scale)
        return data.copy(value = data.value + noise)
    }

    /**
     * Aplica enmascaramiento por tipo de dato
     */
    fun maskByDataType(data: Any, maskingPolicy: MaskingPolicy): Any {
        return when (maskingPolicy) {
            MaskingPolicy.MASK_NAME -> (data as? String)?.replace(Regex("."), "*") ?: data
            MaskingPolicy.MASK_PHONE -> (data as? String)?.replace(Regex("\\d(?=\\d{2})"), "*") ?: data
            MaskingPolicy.MASK_EMAIL -> (data as? String)?.replaceBefore("@", "***") ?: data
            MaskingPolicy.MASK_GENERIC -> "***"
        }
    }

    /**
     * Sistema de retención de datos configurables
     */
    fun enforceRetentionPolicy(data: List<PersonalData>, retentionDays: Int): List<PersonalData> {
        // Aquí simulamos que si retentionDays < 30 borramos los registros antiguos
        return if (retentionDays < 30) {
            emptyList() // Borrado total por política
        } else {
            data // Conserva los datos
        }
    }

    /**
     * Genera ruido Laplaciano para differential privacy
     */
    private fun laplaceNoise(scale: Double): Double {
        val u = Random.nextDouble() - 0.5
        return -scale * kotlin.math.sign(u) * ln(1 - 2 * kotlin.math.abs(u))
    }
}
