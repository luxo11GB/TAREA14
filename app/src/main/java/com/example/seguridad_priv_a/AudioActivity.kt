package com.example.seguridad_priv_a

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.example.seguridad_priv_a.databinding.ActivityAudioBinding

class AudioActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityAudioBinding
    private val dataProtectionManager by lazy { 
        (application as PermissionsApplication).dataProtectionManager 
    }
    
    private var isRecording = false
    private val handler = Handler(Looper.getMainLooper())
    private var recordingRunnable: Runnable? = null
    
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        updatePermissionStatus()
        if (isGranted) {
            dataProtectionManager.logAccess("AUDIO_PERMISSION", "Permiso de micrófono otorgado")
            Toast.makeText(this, "Permiso de micrófono otorgado", Toast.LENGTH_SHORT).show()
        } else {
            dataProtectionManager.logAccess("AUDIO_PERMISSION", "Permiso de micrófono denegado")
            showPermissionDeniedDialog()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAudioBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        updatePermissionStatus()
        
        dataProtectionManager.logAccess("NAVIGATION", "AudioActivity abierta")
    }
    
    private fun setupUI() {
        binding.btnRecordAudio.setOnClickListener {
            if (hasPermission()) {
                if (isRecording) {
                    stopRecording()
                } else {
                    startRecording()
                }
            } else {
                requestAudioPermission()
            }
        }
        
        binding.btnRequestPermission.setOnClickListener {
            requestAudioPermission()
        }
    }
    
    private fun hasPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            this, 
            Manifest.permission.RECORD_AUDIO
        ) == PackageManager.PERMISSION_GRANTED
    }
    
    private fun updatePermissionStatus() {
        val hasPermission = hasPermission()
        
        binding.tvAudioStatus.text = if (hasPermission) {
            "✅ Permiso de micrófono otorgado"
        } else {
            "❌ Permiso de micrófono requerido"
        }
        
        binding.btnRecordAudio.isEnabled = hasPermission
        binding.btnRequestPermission.visibility = if (hasPermission) {
            android.view.View.GONE
        } else {
            android.view.View.VISIBLE
        }
    }
    
    private fun requestAudioPermission() {
        when {
            hasPermission() -> {
                updatePermissionStatus()
            }
            shouldShowRequestPermissionRationale(Manifest.permission.RECORD_AUDIO) -> {
                showPermissionRationaleDialog()
            }
            else -> {
                dataProtectionManager.logAccess("AUDIO_PERMISSION", "Solicitando permiso de micrófono")
                requestPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
            }
        }
    }
    
    private fun showPermissionRationaleDialog() {
        AlertDialog.Builder(this)
            .setTitle("Permiso de Micrófono Necesario")
            .setMessage("Esta aplicación necesita acceso al micrófono para demostrar la grabación de audio. Los datos se procesan localmente y se eliminan automáticamente.")
            .setPositiveButton("Otorgar") { _, _ ->
                requestPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }
    
    private fun showPermissionDeniedDialog() {
        AlertDialog.Builder(this)
            .setTitle("Permiso Denegado")
            .setMessage("El permiso de micrófono ha sido denegado. Para usar esta función, ve a Configuración y otorga el permiso manualmente.")
            .setPositiveButton("Ir a Configuración") { _, _ ->
                openAppSettings()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }
    
    private fun openAppSettings() {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.fromParts("package", packageName, null)
        }
        startActivity(intent)
        dataProtectionManager.logAccess("NAVIGATION", "Configuración de la app abierta")
    }
    
    private fun startRecording() {
        isRecording = true
        binding.btnRecordAudio.text = "Detener Grabación"
        binding.tvRecordingStatus.text = "🔴 Grabando..."
        
        dataProtectionManager.logAccess("AUDIO_ACCESS", "Grabación de audio iniciada")
        
        // Simular grabación por 5 segundos
        recordingRunnable = Runnable {
            stopRecording()
        }
        handler.postDelayed(recordingRunnable!!, 5000)
        
        // Guardar timestamp de la grabación
        dataProtectionManager.storeSecureData("last_recording_time", 
            System.currentTimeMillis().toString())
    }
    
    private fun stopRecording() {
        isRecording = false
        binding.btnRecordAudio.text = getString(R.string.btn_record_audio)
        binding.tvRecordingStatus.text = "✅ Grabación completada y procesada"
        
        recordingRunnable?.let { handler.removeCallbacks(it) }
        
        dataProtectionManager.logAccess("AUDIO_ACCESS", "Grabación de audio completada y procesada")
        dataProtectionManager.logAccess("DATA_SECURITY", "Datos de audio eliminados automáticamente")
        
        Toast.makeText(this, "Grabación procesada y eliminada de forma segura", Toast.LENGTH_SHORT).show()
        
        // Reset después de 3 segundos
        handler.postDelayed({
            binding.tvRecordingStatus.text = "🎤 Listo para grabar"
        }, 3000)
    }
    
    override fun onResume() {
        super.onResume()
        updatePermissionStatus()
    }
    
    override fun onDestroy() {
        super.onDestroy()
        recordingRunnable?.let { handler.removeCallbacks(it) }
    }
}