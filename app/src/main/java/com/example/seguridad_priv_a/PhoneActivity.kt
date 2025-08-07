package com.example.seguridad_priv_a

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.example.seguridad_priv_a.databinding.ActivityPhoneBinding

class PhoneActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityPhoneBinding
    private val dataProtectionManager by lazy { 
        (application as PermissionsApplication).dataProtectionManager 
    }
    
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        updatePermissionStatus()
        if (isGranted) {
            dataProtectionManager.logAccess("PHONE_PERMISSION", "Permiso de teléfono otorgado")
            Toast.makeText(this, "Permiso de teléfono otorgado", Toast.LENGTH_SHORT).show()
        } else {
            dataProtectionManager.logAccess("PHONE_PERMISSION", "Permiso de teléfono denegado")
            showPermissionDeniedDialog()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPhoneBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        updatePermissionStatus()
        
        dataProtectionManager.logAccess("NAVIGATION", "PhoneActivity abierta")
    }
    
    private fun setupUI() {
        binding.btnMakeCall.setOnClickListener {
            if (hasPermission()) {
                simulateCall()
            } else {
                requestPhonePermission()
            }
        }
        
        binding.btnRequestPermission.setOnClickListener {
            requestPhonePermission()
        }
    }
    
    private fun hasPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            this, 
            Manifest.permission.CALL_PHONE
        ) == PackageManager.PERMISSION_GRANTED
    }
    
    private fun updatePermissionStatus() {
        val hasPermission = hasPermission()
        
        binding.tvPhoneStatus.text = if (hasPermission) {
            "✅ Permiso de teléfono otorgado"
        } else {
            "❌ Permiso de teléfono requerido"
        }
        
        binding.btnMakeCall.isEnabled = hasPermission
        binding.btnRequestPermission.visibility = if (hasPermission) {
            android.view.View.GONE
        } else {
            android.view.View.VISIBLE
        }
    }
    
    private fun requestPhonePermission() {
        when {
            hasPermission() -> {
                updatePermissionStatus()
            }
            shouldShowRequestPermissionRationale(Manifest.permission.CALL_PHONE) -> {
                showPermissionRationaleDialog()
            }
            else -> {
                dataProtectionManager.logAccess("PHONE_PERMISSION", "Solicitando permiso de teléfono")
                requestPermissionLauncher.launch(Manifest.permission.CALL_PHONE)
            }
        }
    }
    
    private fun showPermissionRationaleDialog() {
        AlertDialog.Builder(this)
            .setTitle("Permiso de Teléfono Necesario")
            .setMessage("Esta aplicación necesita acceso al teléfono para demostrar las llamadas. En esta demo solo se simula la llamada.")
            .setPositiveButton("Otorgar") { _, _ ->
                requestPermissionLauncher.launch(Manifest.permission.CALL_PHONE)
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }
    
    private fun showPermissionDeniedDialog() {
        AlertDialog.Builder(this)
            .setTitle("Permiso Denegado")
            .setMessage("El permiso de teléfono ha sido denegado. Para usar esta función, ve a Configuración y otorga el permiso manualmente.")
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
    
    private fun simulateCall() {
        val phoneNumber = binding.etPhoneNumber.text.toString().trim()
        
        if (phoneNumber.isEmpty()) {
            Toast.makeText(this, "Ingresa un número de teléfono", Toast.LENGTH_SHORT).show()
            return
        }
        
        // Anonimizar el número para logging
        val anonymizedNumber = dataProtectionManager.anonymizeData(phoneNumber)
        
        // Simular llamada
        AlertDialog.Builder(this)
            .setTitle("Simulación de Llamada")
            .setMessage("Se simuló una llamada al número: $anonymizedNumber\\n\\nEn una aplicación real, esto iniciaría la llamada.")
            .setPositiveButton("OK", null)
            .show()
            
        dataProtectionManager.logAccess("PHONE_ACCESS", "Llamada simulada a número anonimizado: $anonymizedNumber")
        dataProtectionManager.storeSecureData("last_call_timestamp", System.currentTimeMillis().toString())
        
        Toast.makeText(this, "Llamada simulada - Acceso registrado", Toast.LENGTH_SHORT).show()
    }
    
    override fun onResume() {
        super.onResume()
        updatePermissionStatus()
    }
}