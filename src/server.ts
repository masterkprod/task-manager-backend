import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import swaggerUi from 'swagger-ui-express';

import { config, validateConfig } from './config/config';
import { connectDatabase } from './config/database';
import { swaggerSpec } from './config/swagger';

// Importar rutas
import authRoutes from './routes/auth';
import userRoutes from './routes/users';
import taskRoutes from './routes/tasks';

/**
 * Clase principal del servidor
 */
class Server {
  private app: express.Application;
  private port: number;

  constructor() {
    this.app = express();
    this.port = Number(config.port);
    
    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }

  /**
   * Inicializar middlewares
   */
  private initializeMiddlewares(): void {
    // Seguridad
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
    }));

    // CORS
    this.app.use(cors({
      origin: config.frontendUrl,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: config.rateLimit.windowMs,
      max: config.rateLimit.maxRequests,
      message: {
        success: false,
        message: 'Demasiadas solicitudes, intenta de nuevo más tarde',
        code: 'RATE_LIMIT_EXCEEDED',
      },
      standardHeaders: true,
      legacyHeaders: false,
    });
    this.app.use('/api/', limiter);

    // Compresión
    this.app.use(compression());

    // Parsers
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    this.app.use(cookieParser());

    // Logging de requests
    this.app.use((req, res, next) => {
      console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
      next();
    });
  }

  /**
   * Inicializar rutas
   */
  private initializeRoutes(): void {
    // Ruta de salud
    this.app.get('/health', (req, res) => {
      res.json({
        success: true,
        message: 'Servidor funcionando correctamente',
        timestamp: new Date().toISOString(),
        environment: config.nodeEnv,
      });
    });

    // Documentación Swagger
    this.app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
      customCss: '.swagger-ui .topbar { display: none }',
      customSiteTitle: 'Task Manager API Documentation',
    }));

    // Rutas de la API
    this.app.use('/api/auth', authRoutes);
    this.app.use('/api/users', userRoutes);
    this.app.use('/api/tasks', taskRoutes);

    // Ruta 404
    this.app.use('*', (req, res) => {
      res.status(404).json({
        success: false,
        message: 'Endpoint no encontrado',
        code: 'NOT_FOUND',
        path: req.originalUrl,
      });
    });
  }

  /**
   * Inicializar manejo de errores
   */
  private initializeErrorHandling(): void {
    // Middleware de manejo de errores
    this.app.use((error: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
      console.error('Error no manejado:', error);

      // Error de validación de Mongoose
      if (error.name === 'ValidationError') {
        const errors = Object.values(error.errors).map((err: any) => ({
          field: err.path,
          message: err.message,
        }));

        return res.status(400).json({
          success: false,
          message: 'Errores de validación',
          code: 'VALIDATION_ERROR',
          errors,
        });
      }

      // Error de duplicado de Mongoose
      if (error.code === 11000) {
        const field = Object.keys(error.keyValue)[0];
        return res.status(409).json({
          success: false,
          message: `Ya existe un registro con este ${field}`,
          code: 'DUPLICATE_ERROR',
          field,
        });
      }

      // Error de cast de Mongoose
      if (error.name === 'CastError') {
        return res.status(400).json({
          success: false,
          message: 'ID inválido',
          code: 'INVALID_ID',
        });
      }

      // Error de JWT
      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
          success: false,
          message: 'Token inválido',
          code: 'INVALID_TOKEN',
        });
      }

      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: 'Token expirado',
          code: 'TOKEN_EXPIRED',
        });
      }

      // Error genérico
      return res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
        ...(config.nodeEnv === 'development' && { error: error.message }),
      });
    });
  }

  /**
   * Iniciar el servidor
   */
  public async start(): Promise<void> {
    try {
      // Validar configuración
      validateConfig();

      // Conectar a la base de datos
      await connectDatabase();

      // Iniciar servidor
      this.app.listen(this.port, () => {
        console.log('🚀 Servidor iniciado exitosamente');
        console.log(`📍 Puerto: ${this.port}`);
        console.log(`🌍 Entorno: ${config.nodeEnv}`);
        console.log(`📚 Documentación: http://localhost:${this.port}/api-docs`);
        console.log(`❤️  Salud: http://localhost:${this.port}/health`);
      });
    } catch (error) {
      console.error('❌ Error al iniciar el servidor:', error);
      process.exit(1);
    }
  }
}

// Crear e iniciar servidor
const server = new Server();
server.start();

// Manejo de señales para cierre graceful
process.on('SIGTERM', () => {
  console.log('🛑 Señal SIGTERM recibida, cerrando servidor...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 Señal SIGINT recibida, cerrando servidor...');
  process.exit(0);
});

export default server;
