package com.example.seguridad_priv_a.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.util.Base64
import android.widget.Toast
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.KeyStore
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

class AntiTamperingManager(private val context: Context) {

    /**
     * Detección de debugging activo
     */
    fun isDebuggerAttached(): Boolean {
        return Debug.isDebuggerConnected()
    }

    /**
     * Detección de emulador
     */
    fun isRunningOnEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || "google_sdk" == Build.PRODUCT)
    }

    /**
     * Verificación de la firma digital de la aplicación
     * Compatible con minSdk 24
     */
    fun verifyAppSignature(expectedHash: String): Boolean {
        return try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
            }

            val certBytes: ByteArray? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
                    ?.firstOrNull()
                    ?.toByteArray()
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
                    ?.firstOrNull()
                    ?.toByteArray()
            }

            if (certBytes == null) {
                return false
            }

            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(certBytes)
            val calculatedHash = Base64.encodeToString(digest, Base64.NO_WRAP)

            calculatedHash == expectedHash
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    /**
     * Certificate Pinning
     */
    fun configureCertificatePinning(): SSLContext? {
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val caInput = context.assets.open("server_cert.crt") // coloca el cert en assets
            val ca = cf.generateCertificate(caInput)

            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            keyStore.load(null, null)
            keyStore.setCertificateEntry("ca", ca)

            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(keyStore)

            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, tmf.trustManagers, null)
            sslContext
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * Ejecuta verificaciones y muestra alertas
     */
    fun runSecurityChecks() {
        if (isDebuggerAttached()) {
            Toast.makeText(context, "⚠️ Debugging detectado", Toast.LENGTH_LONG).show()
        }

        if (isRunningOnEmulator()) {
            Toast.makeText(context, "⚠️ Emulador detectado", Toast.LENGTH_LONG).show()
        }

        val expectedHash = "TU_HASH_BASE64_AQUI"
        if (!verifyAppSignature(expectedHash)) {
            Toast.makeText(context, "⚠️ Firma digital inválida", Toast.LENGTH_LONG).show()
        }
    }
}

