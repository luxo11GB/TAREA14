# App de Seguridad y Privacidad

Una aplicación Android que demuestra el manejo seguro de permisos y protección de datos personales.

## Características

### Gestión de Permisos
- **Cámara**: Captura de fotos con manejo seguro
- **Galería**: Acceso a imágenes del dispositivo
- **Micrófono**: Grabación de audio con permisos dinámicos
- **Contactos**: Lectura segura de la lista de contactos
- **Teléfono**: Funcionalidad de llamadas
- **Ubicación**: Acceso a localización del usuario

### Seguridad y Privacidad
- **Protección de Datos**: Sistema de logging encriptado
- **Almacenamiento Seguro**: Base de datos SQLCipher
- **Permisos Runtime**: Solicitud dinámica de permisos
- **Política de Privacidad**: Información transparente sobre el uso de datos

## Tecnologías Utilizadas

- **Kotlin**: Lenguaje principal
- **Android Jetpack**: Componentes modernos
- **SQLCipher**: Encriptación de base de datos
- **Camera2 API**: Manejo avanzado de cámara
- **Security Crypto**: Encriptación de datos sensibles

## Instalación

1. Clona el repositorio
2. Abre el proyecto en Android Studio
3. Sincroniza las dependencias
4. Ejecuta en dispositivo o emulador

## Estructura del Proyecto

```
app/
├── src/main/java/com/example/seguridad_priv_a/
│   ├── MainActivity.kt                 # Pantalla principal
│   ├── PermissionsApplication.kt       # Configuración global
│   ├── data/
│   │   ├── DataProtectionManager.kt    # Gestión de datos seguros
│   │   └── PermissionItem.kt          # Modelo de permisos
│   ├── adapter/
│   │   └── PermissionsAdapter.kt      # Adaptador RecyclerView
│   └── [Actividades individuales]
└── res/
    ├── layout/                        # Diseños XML
    ├── values/                        # Recursos y strings
    └── xml/                          # Configuraciones
```

## Permisos Requeridos

- `CAMERA` - Para captura de fotos
- `READ_MEDIA_IMAGES` - Acceso a galería
- `RECORD_AUDIO` - Grabación de audio
- `READ_CONTACTS` - Lectura de contactos
- `CALL_PHONE` - Realizar llamadas
- `ACCESS_COARSE_LOCATION` - Ubicación aproximada

## Licencia

Este proyecto es para fines educativos y demostrativos.