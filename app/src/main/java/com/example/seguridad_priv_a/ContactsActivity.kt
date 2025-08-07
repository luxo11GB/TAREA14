package com.example.seguridad_priv_a

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.provider.ContactsContract
import android.provider.Settings
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.example.seguridad_priv_a.databinding.ActivityContactsBinding

class ContactsActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityContactsBinding
    private val dataProtectionManager by lazy { 
        (application as PermissionsApplication).dataProtectionManager 
    }
    
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        updatePermissionStatus()
        if (isGranted) {
            dataProtectionManager.logAccess("CONTACTS_PERMISSION", "Permiso de contactos otorgado")
            Toast.makeText(this, "Permiso de contactos otorgado", Toast.LENGTH_SHORT).show()
        } else {
            dataProtectionManager.logAccess("CONTACTS_PERMISSION", "Permiso de contactos denegado")
            showPermissionDeniedDialog()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityContactsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        updatePermissionStatus()
        
        dataProtectionManager.logAccess("NAVIGATION", "ContactsActivity abierta")
    }
    
    private fun setupUI() {
        binding.btnViewContacts.setOnClickListener {
            if (hasPermission()) {
                loadContacts()
            } else {
                requestContactsPermission()
            }
        }
        
        binding.btnRequestPermission.setOnClickListener {
            requestContactsPermission()
        }
    }
    
    private fun hasPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            this, 
            Manifest.permission.READ_CONTACTS
        ) == PackageManager.PERMISSION_GRANTED
    }
    
    private fun updatePermissionStatus() {
        val hasPermission = hasPermission()
        
        binding.tvContactsStatus.text = if (hasPermission) {
            "✅ Permiso de contactos otorgado"
        } else {
            "❌ Permiso de contactos requerido"
        }
        
        binding.btnViewContacts.isEnabled = hasPermission
        binding.btnRequestPermission.visibility = if (hasPermission) {
            android.view.View.GONE
        } else {
            android.view.View.VISIBLE
        }
    }
    
    private fun requestContactsPermission() {
        when {
            hasPermission() -> {
                updatePermissionStatus()
            }
            shouldShowRequestPermissionRationale(Manifest.permission.READ_CONTACTS) -> {
                showPermissionRationaleDialog()
            }
            else -> {
                dataProtectionManager.logAccess("CONTACTS_PERMISSION", "Solicitando permiso de contactos")
                requestPermissionLauncher.launch(Manifest.permission.READ_CONTACTS)
            }
        }
    }
    
    private fun showPermissionRationaleDialog() {
        AlertDialog.Builder(this)
            .setTitle("Permiso de Contactos Necesario")
            .setMessage("Esta aplicación necesita acceso a los contactos para demostrar su lectura. Los datos se anonimizan y procesan localmente.")
            .setPositiveButton("Otorgar") { _, _ ->
                requestPermissionLauncher.launch(Manifest.permission.READ_CONTACTS)
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }
    
    private fun showPermissionDeniedDialog() {
        AlertDialog.Builder(this)
            .setTitle("Permiso Denegado")
            .setMessage("El permiso de contactos ha sido denegado. Para usar esta función, ve a Configuración y otorga el permiso manualmente.")
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
    
    private fun loadContacts() {
        try {
            val cursor: Cursor? = contentResolver.query(
                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                arrayOf(
                    ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                    ContactsContract.CommonDataKinds.Phone.NUMBER
                ),
                null, null,
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME + " ASC"
            )
            
            val contactsList = StringBuilder()
            var contactCount = 0
            
            cursor?.use {
                while (it.moveToNext() && contactCount < 10) { // Limitar a 10 contactos
                    val name = it.getString(it.getColumnIndexOrThrow(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME))
                    val phoneNumber = it.getString(it.getColumnIndexOrThrow(ContactsContract.CommonDataKinds.Phone.NUMBER))
                    
                    // Anonimizar datos
                    val anonymizedName = dataProtectionManager.anonymizeData(name)
                    val anonymizedPhone = dataProtectionManager.anonymizeData(phoneNumber)
                    
                    contactsList.append("📞 $anonymizedName: $anonymizedPhone\\n\\n")
                    contactCount++
                }
            }
            
            if (contactCount > 0) {
                binding.tvContactsList.text = "Contactos encontrados (anonimizados):\\n\\n$contactsList\\n(Mostrando primeros $contactCount contactos)"
                dataProtectionManager.logAccess("CONTACTS_ACCESS", "$contactCount contactos leídos y anonimizados")
                dataProtectionManager.storeSecureData("last_contacts_access", System.currentTimeMillis().toString())
            } else {
                binding.tvContactsList.text = "📱 No se encontraron contactos"
                dataProtectionManager.logAccess("CONTACTS_ACCESS", "No se encontraron contactos")
            }
            
        } catch (e: Exception) {
            binding.tvContactsList.text = "❌ Error al cargar contactos: ${e.message}"
            dataProtectionManager.logAccess("CONTACTS_ERROR", "Error al leer contactos: ${e.message}")
        }
    }
    
    override fun onResume() {
        super.onResume()
        updatePermissionStatus()
    }
}