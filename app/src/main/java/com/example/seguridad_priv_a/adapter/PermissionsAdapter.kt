package com.example.seguridad_priv_a.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.example.seguridad_priv_a.data.PermissionHelper
import com.example.seguridad_priv_a.data.PermissionItem
import com.example.seguridad_priv_a.databinding.ItemPermissionBinding

class PermissionsAdapter(
    private val permissions: List<PermissionItem>,
    private val onItemClick: (PermissionItem) -> Unit
) : RecyclerView.Adapter<PermissionsAdapter.PermissionViewHolder>() {

    inner class PermissionViewHolder(private val binding: ItemPermissionBinding) : 
        RecyclerView.ViewHolder(binding.root) {
        
        fun bind(permission: PermissionItem) {
            binding.apply {
                tvPermissionName.text = permission.name
                tvPermissionDescription.text = permission.description
                tvPermissionStatus.text = PermissionHelper.getStatusText(permission.status)
                
                root.setOnClickListener {
                    onItemClick(permission)
                }
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): PermissionViewHolder {
        val binding = ItemPermissionBinding.inflate(
            LayoutInflater.from(parent.context), 
            parent, 
            false
        )
        return PermissionViewHolder(binding)
    }

    override fun onBindViewHolder(holder: PermissionViewHolder, position: Int) {
        holder.bind(permissions[position])
    }

    override fun getItemCount(): Int = permissions.size
    
    fun updatePermissionStatus(permission: PermissionItem) {
        val index = permissions.indexOf(permission)
        if (index != -1) {
            notifyItemChanged(index)
        }
    }
}