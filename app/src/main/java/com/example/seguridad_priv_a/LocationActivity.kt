package com.example.seguridad_priv_a

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.example.seguridad_priv_a.databinding.ActivityLocationBinding
import kotlin.random.Random

class LocationActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityLocationBinding
    private val dataProtectionManager by lazy { 
        (application as PermissionsApplication).dataProtectionManager 
    }
    
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        updatePermissionStatus()
        if (isGranted) {
            dataProtectionManager.logAccess("LOCATION_PERMISSION", "Permiso de ubicación otorgado")
            Toast.makeText(this, "Permiso de ubicación otorgado", Toast.LENGTH_SHORT).show()
        } else {
            dataProtectionManager.logAccess("LOCATION_PERMISSION", "Permiso de ubicación denegado")
            showPermissionDeniedDialog()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLocationBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        updatePermissionStatus()
        
        dataProtectionManager.logAccess("NAVIGATION", "LocationActivity abierta")
    }
    
    private fun setupUI() {
        binding.btnGetLocation.setOnClickListener {
            if (hasPermission()) {
                getSimulatedLocation()
            } else {
                requestLocationPermission()
            }
        }
        
        binding.btnRequestPermission.setOnClickListener {
            requestLocationPermission()
        }
    }
    
    private fun hasPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            this, 
            Manifest.permission.ACCESS_COARSE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
    }
    
    private fun updatePermissionStatus() {
        val hasPermission = hasPermission()
        
        binding.tvLocationStatus.text = if (hasPermission) {
            "✅ Permiso de ubicación otorgado"
        } else {
            "❌ Permiso de ubicación requerido"
        }
        
        binding.btnGetLocation.isEnabled = hasPermission
        binding.btnRequestPermission.visibility = if (hasPermission) {
            android.view.View.GONE
        } else {
            android.view.View.VISIBLE
        }
    }
    
    private fun requestLocationPermission() {
        when {
            hasPermission() -> {
                updatePermissionStatus()
            }
            shouldShowRequestPermissionRationale(Manifest.permission.ACCESS_COARSE_LOCATION) -> {
                showPermissionRationaleDialog()
            }
            else -> {
                dataProtectionManager.logAccess("LOCATION_PERMISSION", "Solicitando permiso de ubicación")
                requestPermissionLauncher.launch(Manifest.permission.ACCESS_COARSE_LOCATION)
            }
        }
    }
    
    private fun showPermissionRationaleDialog() {
        AlertDialog.Builder(this)
            .setTitle("Permiso de Ubicación Necesario")
            .setMessage("Esta aplicación necesita acceso a la ubicación aproximada para demostrar el uso del permiso. Solo se obtiene ubicación de red, no GPS.")
            .setPositiveButton("Otorgar") { _, _ ->
                requestPermissionLauncher.launch(Manifest.permission.ACCESS_COARSE_LOCATION)
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }
    
    private fun showPermissionDeniedDialog() {
        AlertDialog.Builder(this)
            .setTitle("Permiso Denegado")
            .setMessage("El permiso de ubicación ha sido denegado. Para usar esta función, ve a Configuración y otorga el permiso manualmente.")
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
    
    private fun getSimulatedLocation() {
        // Simular obtención de ubicación aproximada
        val randomLat = Random.nextDouble(-90.0, 90.0)
        val randomLng = Random.nextDouble(-180.0, 180.0)
        
        // Redondear para simular precisión de ubicación de red
        val approximateLat = String.format("%.2f", randomLat)
        val approximateLng = String.format("%.2f", randomLng)
        
        binding.tvLocationInfo.text = "📍 Ubicación aproximada obtenida:\\n\\nLatitud: $approximateLat\\nLongitud: $approximateLng\\n\\n🔒 Coordenadas redondeadas por privacidad"
        
        // Anonimizar y almacenar
        val locationData = "$approximateLat,$approximateLng"
        val anonymizedLocation = dataProtectionManager.anonymizeData(locationData)
        
        dataProtectionManager.logAccess("LOCATION_ACCESS", "Ubicación aproximada obtenida: $anonymizedLocation")
        dataProtectionManager.storeSecureData("last_location", anonymizedLocation)
        dataProtectionManager.storeSecureData("last_location_timestamp", System.currentTimeMillis().toString())
        
        Toast.makeText(this, "Ubicación obtenida y registrada de forma segura", Toast.LENGTH_SHORT).show()
    }
    
    override fun onResume() {
        super.onResume()
        updatePermissionStatus()
    }
}