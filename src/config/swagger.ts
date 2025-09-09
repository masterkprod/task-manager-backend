import swaggerJsdoc from 'swagger-jsdoc';
import { config } from './config';

/**
 * Configuración de Swagger
 */
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Task Manager API',
      version: '1.0.0',
      description: 'API REST para gestión de tareas con autenticación JWT y roles de usuario',
      contact: {
        name: 'Tu Nombre',
        email: 'tu.email@ejemplo.com',
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT',
      },
    },
    servers: [
      {
        url: `http://localhost:${config.port}`,
        description: 'Servidor de desarrollo',
      },
      {
        url: 'https://tu-backend-en-render.com',
        description: 'Servidor de producción',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Ingresa tu token JWT en el formato: Bearer <token>',
        },
      },
      schemas: {
        User: {
          type: 'object',
          required: ['name', 'email', 'password'],
          properties: {
            _id: {
              type: 'string',
              description: 'ID único del usuario',
              example: '507f1f77bcf86cd799439011',
            },
            name: {
              type: 'string',
              description: 'Nombre del usuario',
              example: 'Juan Pérez',
              minLength: 2,
              maxLength: 50,
            },
            email: {
              type: 'string',
              format: 'email',
              description: 'Email del usuario',
              example: 'juan@ejemplo.com',
            },
            role: {
              type: 'string',
              enum: ['user', 'admin'],
              description: 'Rol del usuario',
              example: 'user',
            },
            isActive: {
              type: 'boolean',
              description: 'Estado del usuario',
              example: true,
            },
            createdAt: {
              type: 'string',
              format: 'date-time',
              description: 'Fecha de creación',
            },
            updatedAt: {
              type: 'string',
              format: 'date-time',
              description: 'Fecha de última actualización',
            },
          },
        },
        Task: {
          type: 'object',
          required: ['title', 'description'],
          properties: {
            _id: {
              type: 'string',
              description: 'ID único de la tarea',
              example: '507f1f77bcf86cd799439012',
            },
            title: {
              type: 'string',
              description: 'Título de la tarea',
              example: 'Completar documentación',
              minLength: 1,
              maxLength: 100,
            },
            description: {
              type: 'string',
              description: 'Descripción de la tarea',
              example: 'Finalizar la documentación del proyecto',
              minLength: 1,
              maxLength: 500,
            },
            status: {
              type: 'string',
              enum: ['pending', 'in-progress', 'completed'],
              description: 'Estado de la tarea',
              example: 'pending',
            },
            priority: {
              type: 'string',
              enum: ['low', 'medium', 'high'],
              description: 'Prioridad de la tarea',
              example: 'high',
            },
            dueDate: {
              type: 'string',
              format: 'date-time',
              description: 'Fecha de vencimiento',
              example: '2024-12-31T23:59:59.000Z',
            },
            userId: {
              type: 'string',
              description: 'ID del usuario propietario',
              example: '507f1f77bcf86cd799439011',
            },
            createdAt: {
              type: 'string',
              format: 'date-time',
              description: 'Fecha de creación',
            },
            updatedAt: {
              type: 'string',
              format: 'date-time',
              description: 'Fecha de última actualización',
            },
          },
        },
        AuthResponse: {
          type: 'object',
          properties: {
            success: {
              type: 'boolean',
              example: true,
            },
            message: {
              type: 'string',
              example: 'Login exitoso',
            },
            data: {
              type: 'object',
              properties: {
                user: {
                  $ref: '#/components/schemas/User',
                },
                accessToken: {
                  type: 'string',
                  description: 'Token de acceso JWT',
                  example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                },
              },
            },
          },
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            success: {
              type: 'boolean',
              example: false,
            },
            message: {
              type: 'string',
              example: 'Error en la solicitud',
            },
            code: {
              type: 'string',
              example: 'VALIDATION_ERROR',
            },
            errors: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  field: {
                    type: 'string',
                    example: 'email',
                  },
                  message: {
                    type: 'string',
                    example: 'Debe ser un email válido',
                  },
                  value: {
                    type: 'string',
                    example: 'email-invalido',
                  },
                },
              },
            },
          },
        },
        PaginationResponse: {
          type: 'object',
          properties: {
            page: {
              type: 'integer',
              example: 1,
            },
            limit: {
              type: 'integer',
              example: 10,
            },
            total: {
              type: 'integer',
              example: 25,
            },
            pages: {
              type: 'integer',
              example: 3,
            },
          },
        },
      },
    },
    tags: [
      {
        name: 'Autenticación',
        description: 'Endpoints para registro, login y gestión de tokens',
      },
      {
        name: 'Usuarios',
        description: 'Endpoints para gestión de usuarios y perfiles',
      },
      {
        name: 'Tareas',
        description: 'Endpoints para gestión de tareas (CRUD)',
      },
    ],
  },
  apis: ['./src/routes/*.ts'], // Rutas donde están los comentarios de Swagger
};

export const swaggerSpec = swaggerJsdoc(swaggerOptions);
