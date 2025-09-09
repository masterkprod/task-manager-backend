# 🚀 Task Manager Backend

Backend API para la aplicación Task Manager construido con Express.js, TypeScript y MongoDB.

## 🛠️ Tecnologías

- **Express.js** - Framework web para Node.js
- **TypeScript** - Tipado estático para JavaScript
- **MongoDB** - Base de datos NoSQL
- **Mongoose** - ODM para MongoDB
- **JWT** - Autenticación con tokens
- **Swagger** - Documentación de API
- **Express Validator** - Validación de datos
- **Helmet** - Seguridad HTTP
- **CORS** - Cross-Origin Resource Sharing

## 📋 Características

### 🔐 Autenticación y Seguridad
- Autenticación JWT con access y refresh tokens
- Cookies httpOnly para máxima seguridad
- Roles de usuario (user/admin) con permisos
- Rate limiting para prevenir abuso
- Validación robusta de datos
- Headers de seguridad con Helmet

### 📊 API REST
- CRUD completo de tareas
- Gestión de usuarios con roles
- Estadísticas de productividad
- Filtros y búsqueda avanzada
- Paginación para grandes volúmenes
- Documentación Swagger completa

## 🚀 Instalación

### Prerrequisitos
- Node.js 18+
- MongoDB (local o Atlas)
- npm o yarn

### 1. Instalar dependencias
```bash
npm install
```

### 2. Configurar variables de entorno
```bash
cp env.example .env
```

Editar el archivo `.env`:
```env
PORT=5000
NODE_ENV=development
MONGODB_URI=mongodb://localhost:27017/task-manager
JWT_ACCESS_SECRET=ccess_secret
JWT_REFRESH_SECRET=refresh_secret
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d
FRONTEND_URL=http://localhost:3000
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

### 3. Iniciar servidor
```bash
# Desarrollo
npm run dev

# Producción
npm run build
npm start
```

## 📚 Documentación de la API

### Swagger UI
Una vez iniciado el servidor, visita:
```
http://localhost:5000/api-docs
```

### Endpoints Principales

#### Autenticación
```
POST   /api/auth/register    # Registro de usuario
POST   /api/auth/login       # Inicio de sesión
POST   /api/auth/logout      # Cerrar sesión
POST   /api/auth/refresh     # Refrescar token
GET    /api/auth/profile     # Obtener perfil
```

#### Usuarios
```
PUT    /api/users/profile           # Actualizar perfil
PUT    /api/users/change-password   # Cambiar contraseña
PUT    /api/users/deactivate        # Desactivar cuenta
GET    /api/users                   # Obtener usuarios (admin)
GET    /api/users/:id               # Obtener usuario por ID (admin)
PUT    /api/users/:id               # Actualizar usuario (admin)
DELETE /api/users/:id               # Eliminar usuario (admin)
```

#### Tareas
```
POST   /api/tasks           # Crear tarea
GET    /api/tasks           # Obtener tareas
GET    /api/tasks/stats     # Obtener estadísticas
GET    /api/tasks/:id       # Obtener tarea por ID
PUT    /api/tasks/:id       # Actualizar tarea
DELETE /api/tasks/:id       # Eliminar tarea
```

### Colección de Postman
Importa el archivo `postman-collection.json` en Postman para probar todos los endpoints.

## 🏗️ Arquitectura

```
src/
├── config/          # Configuración de la aplicación
│   ├── config.ts    # Variables de entorno
│   ├── database.ts  # Conexión a MongoDB
│   └── swagger.ts   # Configuración de Swagger
├── controllers/     # Controladores de rutas
│   ├── authController.ts
│   ├── userController.ts
│   └── taskController.ts
├── models/          # Modelos de MongoDB
│   ├── User.ts
│   └── Task.ts
├── routes/          # Definición de rutas
│   ├── auth.ts
│   ├── users.ts
│   └── tasks.ts
├── middlewares/     # Middlewares personalizados
│   ├── auth.ts      # Autenticación y autorización
│   └── validation.ts # Validación de datos
├── services/        # Lógica de negocio
│   └── authService.ts
├── utils/           # Utilidades
└── server.ts        # Punto de entrada
```

## 🔧 Scripts

```bash
npm run dev          # Servidor de desarrollo con nodemon
npm run build        # Compilar TypeScript
npm run start        # Servidor de producción
npm run lint         # Ejecutar ESLint
npm run lint:fix     # Corregir errores de ESLint
npm run format       # Formatear código con Prettier
```

## 🧪 Testing

### Linting
```bash
npm run lint
```

### Formateo
```bash
npm run format
```

## 🚀 Deployment

### Render.com
1. Conecta tu repositorio a Render
2. Usa el archivo `render.yaml` para configuración automática
3. Configura las variables de entorno en el dashboard
4. Deploy automático en cada push

### Variables de entorno para producción
```env
NODE_ENV=production
MONGODB_URI=mongodb+srv://usuario:password@cluster.mongodb.net/task-manager
JWT_ACCESS_SECRET=secreto_super_seguro_para_produccion
JWT_REFRESH_SECRET=otro_secreto_super_seguro_para_produccion
FRONTEND_URL=https://tu-frontend.vercel.app
```

## 🔒 Seguridad

### Implementado
- ✅ Autenticación JWT con refresh tokens
- ✅ Cookies httpOnly y secure
- ✅ Rate limiting
- ✅ Validación de entrada
- ✅ Headers de seguridad (Helmet)
- ✅ CORS configurado
- ✅ Sanitización de datos

### Recomendaciones adicionales
- Usar HTTPS en producción
- Implementar logging de seguridad
- Configurar firewall
- Monitoreo de intentos de acceso
- Backup regular de la base de datos

## 📊 Monitoreo

### Health Check
```
GET /health
```

Respuesta:
```json
{
  "success": true,
  "message": "Servidor funcionando correctamente",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "environment": "development"
}
```

## 📄 Licencia

MIT License - ver el archivo LICENSE para más detalles.
