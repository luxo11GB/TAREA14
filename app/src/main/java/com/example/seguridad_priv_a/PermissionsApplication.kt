package com.example.seguridad_priv_a

import android.app.Application
import com.example.seguridad_priv_a.DataProtectionManager

class PermissionsApplication : Application() {
    
    val dataProtectionManager by lazy {
        DataProtectionManager(this)
    }
    
    override fun onCreate() {
        super.onCreate()
        
        // Inicializar el sistema de protección de datos
        dataProtectionManager.initialize()
        
        // Log de inicio de aplicación
        dataProtectionManager.logAccess("APPLICATION", "App iniciada")
    }
}