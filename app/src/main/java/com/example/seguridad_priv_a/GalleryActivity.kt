package com.example.seguridad_priv_a

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.MediaStore
import android.provider.Settings
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.example.seguridad_priv_a.databinding.ActivityGalleryBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class GalleryActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityGalleryBinding
    private val dataProtectionManager by lazy { 
        (application as PermissionsApplication).dataProtectionManager 
    }
    
    private val requiredPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        Manifest.permission.READ_MEDIA_IMAGES
    } else {
        Manifest.permission.READ_EXTERNAL_STORAGE
    }
    
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        updatePermissionStatus()
        if (isGranted) {
            dataProtectionManager.logAccess("GALLERY_PERMISSION", "Permiso de galería otorgado")
            Toast.makeText(this, "Permiso de galería otorgado", Toast.LENGTH_SHORT).show()
        } else {
            dataProtectionManager.logAccess("GALLERY_PERMISSION", "Permiso de galería denegado")
            showPermissionDeniedDialog()
        }
    }
    
    private val selectImageLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            handleSelectedImage(uri)
        } else {
            dataProtectionManager.logAccess("GALLERY_ACCESS", "Selección de imagen cancelada")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityGalleryBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        updatePermissionStatus()
        loadLastSelectedImage()
        
        dataProtectionManager.logAccess("NAVIGATION", "GalleryActivity abierta")
    }
    
    private fun setupUI() {
        binding.btnSelectImage.setOnClickListener {
            if (hasPermission()) {
                selectImage()
            } else {
                requestGalleryPermission()
            }
        }
        
        binding.btnRequestPermission.setOnClickListener {
            requestGalleryPermission()
        }
    }
    
    private fun hasPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            this, 
            requiredPermission
        ) == PackageManager.PERMISSION_GRANTED
    }
    
    private fun updatePermissionStatus() {
        val hasPermission = hasPermission()
        
        binding.tvGalleryStatus.text = if (hasPermission) {
            "✅ Permiso de galería otorgado"
        } else {
            "❌ Permiso de galería requerido"
        }
        
        binding.btnSelectImage.isEnabled = hasPermission
        binding.btnRequestPermission.visibility = if (hasPermission) {
            android.view.View.GONE
        } else {
            android.view.View.VISIBLE
        }
    }
    
    private fun requestGalleryPermission() {
        when {
            hasPermission() -> {
                updatePermissionStatus()
            }
            shouldShowRequestPermissionRationale(requiredPermission) -> {
                showPermissionRationaleDialog()
            }
            else -> {
                dataProtectionManager.logAccess("GALLERY_PERMISSION", "Solicitando permiso de galería")
                requestPermissionLauncher.launch(requiredPermission)
            }
        }
    }
    
    private fun showPermissionRationaleDialog() {
        AlertDialog.Builder(this)
            .setTitle("Permiso de Galería Necesario")
            .setMessage("Esta aplicación necesita acceso a la galería para seleccionar imágenes de demostración. El acceso se registra de forma segura para propósitos de auditoría.")
            .setPositiveButton("Otorgar") { _, _ ->
                requestPermissionLauncher.launch(requiredPermission)
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }
    
    private fun showPermissionDeniedDialog() {
        AlertDialog.Builder(this)
            .setTitle("Permiso Denegado")
            .setMessage("El permiso de galería ha sido denegado. Para usar esta función, ve a Configuración y otorga el permiso manualmente.")
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
    
    private fun selectImage() {
        selectImageLauncher.launch("image/*")
        dataProtectionManager.logAccess("GALLERY_ACCESS", "Iniciando selección de imagen")
    }
    
    private fun handleSelectedImage(uri: Uri) {
        try {
            binding.ivSelectedImage.setImageURI(uri)
            
            // Obtener información de la imagen
            val imageInfo = getImageInfo(uri)
            binding.tvImageInfo.text = imageInfo
            
            // Guardar referencia de forma segura (anonimizada)
            val anonymizedUri = dataProtectionManager.anonymizeData(uri.toString())
            dataProtectionManager.storeSecureData("last_selected_image", anonymizedUri)
            dataProtectionManager.storeSecureData("last_image_access_time", 
                System.currentTimeMillis().toString())
            
            dataProtectionManager.logAccess("GALLERY_ACCESS", "Imagen seleccionada y procesada")
            Toast.makeText(this, "Imagen cargada y acceso registrado", Toast.LENGTH_SHORT).show()
            
        } catch (e: Exception) {
            dataProtectionManager.logAccess("GALLERY_ERROR", "Error al procesar imagen: ${e.message}")
            Toast.makeText(this, "Error al cargar la imagen", Toast.LENGTH_SHORT).show()
        }
    }
    
    private fun getImageInfo(uri: Uri): String {
        return try {
            val cursor = contentResolver.query(uri, null, null, null, null)
            cursor?.use {
                if (it.moveToFirst()) {
                    val displayNameIndex = it.getColumnIndex(MediaStore.Images.Media.DISPLAY_NAME)
                    val sizeIndex = it.getColumnIndex(MediaStore.Images.Media.SIZE)
                    val dateIndex = it.getColumnIndex(MediaStore.Images.Media.DATE_ADDED)
                    
                    val displayName = if (displayNameIndex >= 0) it.getString(displayNameIndex) else "Desconocido"
                    val size = if (sizeIndex >= 0) it.getLong(sizeIndex) else 0L
                    val dateAdded = if (dateIndex >= 0) it.getLong(dateIndex) else 0L
                    
                    val sizeKB = size / 1024
                    val date = SimpleDateFormat("dd/MM/yyyy", Locale.getDefault()).format(Date(dateAdded * 1000))
                    
                    "📁 $displayName\\n📏 ${sizeKB}KB\\n📅 $date"
                } else {
                    "Información no disponible"
                }
            } ?: "Información no disponible"
        } catch (e: Exception) {
            dataProtectionManager.logAccess("GALLERY_ERROR", "Error al obtener info de imagen: ${e.message}")
            "Error al obtener información"
        }
    }
    
    private fun loadLastSelectedImage() {
        val lastImageTime = dataProtectionManager.getSecureData("last_image_access_time")
        lastImageTime?.let { timeStr ->
            try {
                val time = timeStr.toLong()
                val date = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault()).format(Date(time))
                binding.tvImageInfo.text = "Último acceso: $date"
                dataProtectionManager.logAccess("DATA_ACCESS", "Información de último acceso cargada")
            } catch (e: Exception) {
                dataProtectionManager.logAccess("DATA_ERROR", "Error al cargar último acceso: ${e.message}")
            }
        }
    }
    
    override fun onResume() {
        super.onResume()
        updatePermissionStatus()
    }
}