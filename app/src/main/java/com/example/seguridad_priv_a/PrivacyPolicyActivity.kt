package com.example.seguridad_priv_a

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.example.seguridad_priv_a.databinding.ActivityPrivacyPolicyBinding

class PrivacyPolicyActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityPrivacyPolicyBinding
    private val dataProtectionManager by lazy { 
        (application as PermissionsApplication).dataProtectionManager 
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPrivacyPolicyBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        dataProtectionManager.logAccess("NAVIGATION", "PrivacyPolicyActivity abierta")
        dataProtectionManager.logAccess("PRIVACY", "Usuario consultó política de privacidad")
    }
}