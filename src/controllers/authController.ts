import { Request, Response } from 'express';
import { User } from '../models/User';
import { AuthService } from '../services/authService';
import { config } from '../config/config';

/**
 * Controlador de autenticación
 */
export class AuthController {
  /**
   * Registro de nuevo usuario
   */
  static async register(req: Request, res: Response): Promise<void> {
    try {
      const { name, email, password } = req.body;

      // Verificar si el usuario ya existe
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        res.status(409).json({
          success: false,
          message: 'Ya existe un usuario con este email',
          code: 'USER_EXISTS',
        });
        return;
      }

      // Crear nuevo usuario
      const user = new User({
        name,
        email,
        password,
        role: 'user', // Por defecto todos son usuarios
      });

      await user.save();

      // Generar tokens
      const { accessToken, refreshToken } = AuthService.generateTokenPair(user);

      // Configurar cookie para refresh token
      res.cookie('refreshToken', refreshToken, {
        ...config.cookies,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
      });

      res.status(201).json({
        success: true,
        message: 'Usuario registrado exitosamente',
        data: {
          user: user.toJSON(),
          accessToken,
        },
      });
    } catch (error) {
      console.error('Error en registro:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Login de usuario
   */
  static async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body;

      // Buscar usuario incluyendo la contraseña
      const user = await User.findOne({ email }).select('+password');
      if (!user) {
        res.status(401).json({
          success: false,
          message: 'Credenciales inválidas',
          code: 'INVALID_CREDENTIALS',
        });
        return;
      }

      // Verificar si el usuario está activo
      if (!user.isActive) {
        res.status(401).json({
          success: false,
          message: 'Usuario desactivado',
          code: 'USER_INACTIVE',
        });
        return;
      }

      // Verificar contraseña
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        res.status(401).json({
          success: false,
          message: 'Credenciales inválidas',
          code: 'INVALID_CREDENTIALS',
        });
        return;
      }

      // Generar tokens
      const { accessToken, refreshToken } = AuthService.generateTokenPair(user);

      // Configurar cookie para refresh token
      res.cookie('refreshToken', refreshToken, {
        ...config.cookies,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
      });

      res.json({
        success: true,
        message: 'Login exitoso',
        data: {
          user: user.toJSON(),
          accessToken,
        },
      });
    } catch (error) {
      console.error('Error en login:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Logout de usuario
   */
  static async logout(req: Request, res: Response): Promise<void> {
    try {
      // Limpiar cookie de refresh token
      res.clearCookie('refreshToken', {
        ...config.cookies,
      });

      res.json({
        success: true,
        message: 'Logout exitoso',
      });
    } catch (error) {
      console.error('Error en logout:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Refrescar access token
   */
  static async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const refreshToken = req.cookies.refreshToken;

      if (!refreshToken) {
        res.status(401).json({
          success: false,
          message: 'Refresh token no encontrado',
          code: 'MISSING_REFRESH_TOKEN',
        });
        return;
      }

      // Verificar refresh token
      const { userId } = AuthService.verifyRefreshToken(refreshToken);

      // Buscar usuario
      const user = await User.findById(userId);
      if (!user || !user.isActive) {
        res.status(401).json({
          success: false,
          message: 'Usuario no encontrado o inactivo',
          code: 'USER_NOT_FOUND',
        });
        return;
      }

      // Generar nuevo access token
      const newAccessToken = AuthService.refreshAccessToken(refreshToken, user);

      res.json({
        success: true,
        message: 'Token refrescado exitosamente',
        data: {
          accessToken: newAccessToken,
        },
      });
    } catch (error) {
      console.error('Error al refrescar token:', error);
      res.status(401).json({
        success: false,
        message: error instanceof Error ? error.message : 'Token inválido',
        code: 'INVALID_REFRESH_TOKEN',
      });
    }
  }

  /**
   * Obtener perfil del usuario autenticado
   */
  static async getProfile(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Usuario no autenticado',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      res.json({
        success: true,
        data: {
          user: req.user.toJSON(),
        },
      });
    } catch (error) {
      console.error('Error al obtener perfil:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }
}
