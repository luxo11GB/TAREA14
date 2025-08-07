package com.example.seguridad_priv_a

import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.example.seguridad_priv_a.databinding.ActivityDataProtectionBinding
import com.example.seguridad_priv_a.security.ZeroTrustManager
import com.example.seguridad_priv_a.security.AntiTamperingManager
import java.util.concurrent.Executor

class DataProtectionActivity : AppCompatActivity() {

    private lateinit var binding: ActivityDataProtectionBinding
    private val dataProtectionManager by lazy {
        (application as PermissionsApplication).dataProtectionManager
    }

    // Zero Trust
    private lateinit var zeroTrustManager: ZeroTrustManager
    private var currentToken: String? = null

    // Anti-Tampering
    private lateinit var antiTamperingManager: AntiTamperingManager

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    private val sessionHandler = Handler(Looper.getMainLooper())
    private var sessionRunnable: Runnable? = null
    private val sessionTimeoutMillis: Long = 5 * 60 * 1000 // 5 minutos

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDataProtectionBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Inicializar Zero Trust Manager
        zeroTrustManager = ZeroTrustManager(this, dataProtectionManager)

        // Inicializar AntiTamperingManager
        antiTamperingManager = AntiTamperingManager(this, dataProtectionManager)

        // Hash esperado de la firma SHA-256 (obtenido con keytool)
        val expectedSignatureHash = "TU_HASH_SHA256_AQUI"

        // Certificado en res/raw para certificate pinning
        val certResourceId = R.raw.server_cert

        // Ejecutar validaciones anti-tampering
        if (!antiTamperingManager.runSecurityChecks(expectedSignatureHash, certResourceId)) {
            Toast.makeText(this, "⚠️ Seguridad comprometida. Cerrando la aplicación.", Toast.LENGTH_LONG).show()
            finish()
            return
        }

        setupBiometricAuth()
        setupUI()

        // Autenticación antes de mostrar logs
        authenticateUser()

        dataProtectionManager.logAccess("NAVIGATION", "DataProtectionActivity abierta")
    }

    private fun setupBiometricAuth() {
        executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Toast.makeText(applicationContext, "Autenticación exitosa", Toast.LENGTH_SHORT).show()

                    // Generar token para sesión Zero Trust
                    currentToken = zeroTrustManager.generateSessionToken()

                    loadDataProtectionInfo()
                    loadAccessLogs()
                    startSessionTimeout()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(applicationContext, "Error de autenticación: $errString", Toast.LENGTH_SHORT).show()
                    showPinFallbackDialog()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "Autenticación fallida", Toast.LENGTH_SHORT).show()
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Autenticación requerida")
            .setSubtitle("Use su huella digital o rostro para acceder")
            .setNegativeButtonText("Usar PIN/Patrón")
            .build()
    }

    private fun authenticateUser() {
        val biometricManager = BiometricManager.from(this)
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)) {
            BiometricManager.BIOMETRIC_SUCCESS -> biometricPrompt.authenticate(promptInfo)
            else -> showPinFallbackDialog() // fallback a PIN
        }
    }

    private fun showPinFallbackDialog() {
        val sharedPref = getSharedPreferences("AppPrefs", Context.MODE_PRIVATE)
        val savedPin = sharedPref.getString("user_pin", "1234") // default para demo

        val input = android.widget.EditText(this)
        input.inputType = android.text.InputType.TYPE_CLASS_NUMBER or
                android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD

        AlertDialog.Builder(this)
            .setTitle("Ingrese su PIN")
            .setView(input)
            .setPositiveButton("Validar") { _, _ ->
                if (input.text.toString() == savedPin) {
                    Toast.makeText(this, "PIN correcto", Toast.LENGTH_SHORT).show()
                    currentToken = zeroTrustManager.generateSessionToken()
                    loadDataProtectionInfo()
                    loadAccessLogs()
                    startSessionTimeout()
                } else {
                    Toast.makeText(this, "PIN incorrecto", Toast.LENGTH_SHORT).show()
                    finish()
                }
            }
            .setNegativeButton("Cancelar") { _, _ -> finish() }
            .show()
    }

    private fun startSessionTimeout() {
        sessionRunnable?.let { sessionHandler.removeCallbacks(it) }
        sessionRunnable = Runnable {
            Toast.makeText(this, "Sesión expirada por inactividad", Toast.LENGTH_LONG).show()
            finish()
        }
        sessionHandler.postDelayed(sessionRunnable!!, sessionTimeoutMillis)
    }

    private fun resetSessionTimeout() {
        sessionRunnable?.let { sessionHandler.removeCallbacks(it) }
        sessionRunnable?.let { sessionHandler.postDelayed(it, sessionTimeoutMillis) }
    }

    private fun setupUI() {
        binding.btnViewLogs.setOnClickListener {
            if (zeroTrustManager.validateSensitiveOperation("VER_LOGS", currentToken)) {
                loadAccessLogs()
            } else {
                Toast.makeText(this, "Acceso no autorizado", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnClearData.setOnClickListener {
            if (zeroTrustManager.validateSensitiveOperation("BORRAR_DATOS", currentToken)) {
                showClearDataDialog()
            } else {
                Toast.makeText(this, "Acción no autorizada", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun loadDataProtectionInfo() {
        val info = dataProtectionManager.getDataProtectionInfo()
        val infoText = StringBuilder()

        infoText.append("🔐 INFORMACIÓN DE SEGURIDAD\n\n")
        info.forEach { (key, value) -> infoText.append("• $key: $value\n") }

        infoText.append("\n📊 EVIDENCIAS DE PROTECCIÓN:\n")
        infoText.append("• Encriptación AES-256-GCM activa\n")
        infoText.append("• Todos los accesos registrados\n")
        infoText.append("• Datos anonimizados automáticamente\n")
        infoText.append("• Almacenamiento local seguro\n")
        infoText.append("• No hay compartición de datos\n")

        binding.tvDataProtectionInfo.text = infoText.toString()

        dataProtectionManager.logAccess("DATA_PROTECTION", "Información de protección mostrada")
    }

    private fun loadAccessLogs() {
        val logs = dataProtectionManager.getAccessLogs()
        binding.tvAccessLogs.text = if (logs.isNotEmpty()) logs.joinToString("\n") else "No hay logs disponibles"
        dataProtectionManager.logAccess("DATA_ACCESS", "Logs de acceso consultados")
    }

    private fun showClearDataDialog() {
        AlertDialog.Builder(this)
            .setTitle("Borrar Todos los Datos")
            .setMessage("¿Estás seguro de que deseas borrar todos los datos almacenados y logs de acceso? Esta acción no se puede deshacer.")
            .setPositiveButton("Borrar") { _, _ -> clearAllData() }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun clearAllData() {
        dataProtectionManager.clearAllData()
        binding.tvAccessLogs.text = "Todos los datos han sido borrados"
        binding.tvDataProtectionInfo.text = "🔐 DATOS BORRADOS DE FORMA SEGURA\n\nTodos los datos personales y logs han sido eliminados del dispositivo."
        Toast.makeText(this, "Datos borrados de forma segura", Toast.LENGTH_LONG).show()
        dataProtectionManager.logAccess("DATA_MANAGEMENT", "Todos los datos borrados por el usuario")
    }

    override fun onResume() {
        super.onResume()
        resetSessionTimeout()
    }

    override fun onPause() {
        super.onPause()
        sessionRunnable?.let { sessionHandler.removeCallbacks(it) }
    }
}


