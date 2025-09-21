# 🎯 Task Manager - Aplicación Fullstack CRUD

Una aplicación moderna y completa para gestión de tareas con autenticación JWT, roles de usuario y una interfaz atractiva.

## ✨ Características Principales

### 🔐 Autenticación y Seguridad
- **Autenticación JWT** con access tokens y refresh tokens seguros
- **Cookies httpOnly** para máxima seguridad
- **Roles de usuario** (usuario/admin) con permisos diferenciados
- **Validación robusta** de datos de entrada
- **Rate limiting** para prevenir abuso
- **Helmet** para headers de seguridad

### 📋 Gestión de Tareas
- **CRUD completo** de tareas con estados y prioridades
- **Filtros avanzados** por estado, prioridad, fecha y búsqueda
- **Estadísticas detalladas** de productividad
- **Fechas de vencimiento** con alertas
- **Paginación** para grandes volúmenes de datos

### 🎨 Interfaz de Usuario
- **Diseño moderno** con TailwindCSS
- **Responsive design** para todos los dispositivos
- **Animaciones suaves** y transiciones
- **Tema atractivo** con gradientes y sombras
- **Componentes reutilizables**
- **UX optimizada**

### 🛠️ Tecnologías

#### Frontend
- **Next.js 14** con App Router
- **React 18** con TypeScript
- **TailwindCSS** para estilos
- **@tanstack/react-query** para manejo de estado
- **React Hook Form** para formularios
- **Lucide React** para iconos

#### Backend
- **Express.js** con TypeScript
- **MongoDB** con Mongoose ODM
- **JWT** para autenticación
- **Swagger** para documentación
- **Express Validator** para validación
- **Helmet** para seguridad

## 🚀 Instalación y Configuración

### Prerrequisitos
- Node.js 18+ 
- MongoDB (local o Atlas)
- npm o yarn

### 1. Clonar el repositorio
```bash
git clone https://github.com/masterkprod/task-manager-backend
cd task-manager-backend
```

### 2. Configurar Variables de Entorno

#### Frontend (Next.js)
```bash
# Crear archivo de configuración
cp env.example .env.local
```

**Configuración requerida:**
```env
# URL del backend API (SIN barra final)
NEXT_PUBLIC_API_URL=http://localhost:5000
```

**Para diferentes entornos:**
- **Desarrollo local**: `http://localhost:5000`
- **Backend en Render**: `https://task-manager-backend-hgdg.onrender.com`
- **Backend personalizado**: `https://tu-dominio.com`

#### Backend (Express.js)
```bash
# Crear archivo de configuración
cp env.example .env
```

**Configuración requerida:**
```env
PORT=5000
NODE_ENV=development
MONGODB_URI=mongodb://localhost:27017/task-manager
JWT_ACCESS_SECRET=tu_access_secret_super_seguro
JWT_REFRESH_SECRET=tu_refresh_secret_super_seguro
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d
FRONTEND_URL=http://localhost:3000
```

### 3. Instalar Dependencias

```bash
# Instalar dependencias del frontend
npm install

# Si tienes backend separado, instalar también:
# cd Back && npm install
```

### 4. Configurar CORS (IMPORTANTE)

**Para que la aplicación funcione correctamente, tu backend DEBE configurar CORS para permitir tu dominio frontend:**

```javascript
// En tu backend (Express.js)
const cors = require('cors');

app.use(cors({
  origin: [
    'http://localhost:3000',           // Desarrollo local
    'https://tu-app.vercel.app',       // Producción Vercel
    'https://tu-dominio.com'           // Tu dominio personalizado
  ],
  credentials: true
}));
```

### 5. Iniciar la Aplicación

```bash
# Iniciar servidor de desarrollo
npm run dev
```

**URLs disponibles:**
- **Frontend**: `http://localhost:3000`
- **Backend** (si está local): `http://localhost:5000`
- **API**: `http://localhost:5000/api`
- **Documentación**: `http://localhost:5000/api-docs`

### 6. Verificar Configuración

**Para verificar que todo está configurado correctamente:**
1. Visita `http://localhost:3000?config=true` para ver información de configuración
2. Revisa la consola del navegador para errores de CORS
3. Verifica que las variables de entorno estén cargadas correctamente

### 7. Backend Disponible

**Backend de demo está desplegado en Render:**
- **URL**: `https://task-manager-backend-hgdg.onrender.com`
- **API**: `https://task-manager-backend-hgdg.onrender.com/api`
- **Documentación**: `https://task-manager-backend-hgdg.onrender.com/api-docs`
- **Health Check**: `https://task-manager-backend-hgdg.onrender.com/health`

**Credenciales de demostración:**
- **Usuario**: `usuario@ejemplo.com`
- **Contraseña**: `password123`

## 📁 Estructura del Proyecto

```
Task Manager/
├── Back/                    # Backend (Express + MongoDB)
│   ├── src/
│   │   ├── config/         # Configuración
│   │   ├── controllers/    # Controladores
│   │   ├── models/         # Modelos de MongoDB
│   │   ├── routes/         # Rutas de la API
│   │   ├── middlewares/    # Middlewares
│   │   ├── services/       # Servicios
│   │   └── utils/          # Utilidades
│   ├── postman-collection.json
│   └── render.yaml
├── Front/                   # Frontend (Next.js + React)
│   ├── src/
│   │   ├── app/           # Páginas (App Router)
│   │   ├── components/    # Componentes React
│   │   ├── hooks/         # Hooks personalizados
│   │   ├── lib/           # Utilidades y API client
│   │   ├── types/         # Tipos TypeScript
│   │   └── styles/        # Estilos globales
│   └── vercel.json
└── README.md
```

## 🔧 Scripts Disponibles

### Backend
- `npm run dev` - Servidor de desarrollo
- `npm run build` - Compilar para producción
- `npm run start` - Servidor de producción
- `npm run lint` - Linter
- `npm run format` - Formatear código

### Frontend
- `npm run dev` - Servidor de desarrollo
- `npm run build` - Compilar para producción
- `npm run start` - Servidor de producción
- `npm run lint` - Linter
- `npm run format` - Formatear código
- `npm run type-check` - Verificar tipos

## 🚀 Deployment

### Frontend en Vercel
1. Conecta tu repositorio a Vercel
2. Configura las variables de entorno:
   - `NEXT_PUBLIC_API_URL`: URL de tu backend en Render
3. Deploy automático en cada push

### Backend en Render
1. Conecta tu repositorio a Render
2. Usa el archivo `render.yaml` para configuración automática
3. Configura las variables de entorno en el dashboard
4. Deploy automático en cada push

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## 👨‍💻 Autor

**Master K**
- GitHub: [@masterkprod](https://github.com/masterkprod)
- LinkedIn: [Gonzalo Vega](https://www.linkedin.com/in/gonzalo-jesus-vega/)
- Email: masterkprod@gmail.com

---

⭐ **¡Si te gusta este proyecto, no olvides darle una estrella!** ⭐
