import { Request, Response, NextFunction } from 'express';
import { AuthService, JWTPayload } from '../services/authService';
import { User, IUser } from '../models/User';

/**
 * Extender la interfaz Request para incluir el usuario autenticado
 */
declare global {
  namespace Express {
    interface Request {
      user?: IUser;
      tokenPayload?: JWTPayload;
    }
  }
}

/**
 * Middleware de autenticación
 * Verifica el token JWT y carga el usuario en la request
 */
export const authenticate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    // Obtener el token del header Authorization
    const authHeader = req.headers.authorization;
    
    console.log('Auth middleware - Authorization header:', authHeader);
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.log('Auth middleware - Missing or invalid authorization header');
      res.status(401).json({
        success: false,
        message: 'Token de acceso requerido',
        code: 'MISSING_TOKEN',
      });
      return;
    }

    const token = authHeader.substring(7); // Remover 'Bearer '
    console.log('Auth middleware - Token:', token.substring(0, 20) + '...');

    // Verificar el token
    const payload = AuthService.verifyAccessToken(token);
    console.log('Auth middleware - Token payload:', payload);
    
    // Buscar el usuario en la base de datos
    const user = await User.findById(payload.userId).select('+isActive');
    console.log('Auth middleware - User found:', user ? 'Yes' : 'No');
    
    if (!user) {
      console.log('Auth middleware - User not found');
      res.status(401).json({
        success: false,
        message: 'Usuario no encontrado',
        code: 'USER_NOT_FOUND',
      });
      return;
    }

    if (!user.isActive) {
      console.log('Auth middleware - User inactive');
      res.status(401).json({
        success: false,
        message: 'Usuario desactivado',
        code: 'USER_INACTIVE',
      });
      return;
    }

    // Agregar usuario y payload a la request
    req.user = user;
    req.tokenPayload = payload;
    console.log('Auth middleware - Authentication successful');
    
    next();
  } catch (error) {
    console.log('Auth middleware - Error:', error);
    res.status(401).json({
      success: false,
      message: error instanceof Error ? error.message : 'Token inválido',
      code: 'INVALID_TOKEN',
    });
  }
};

/**
 * Middleware de autorización por roles
 * Verifica que el usuario tenga el rol requerido
 */
export const authorize = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        message: 'Usuario no autenticado',
        code: 'NOT_AUTHENTICATED',
      });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(403).json({
        success: false,
        message: 'No tienes permisos para realizar esta acción',
        code: 'INSUFFICIENT_PERMISSIONS',
        requiredRoles: roles,
        userRole: req.user.role,
      });
      return;
    }

    next();
  };
};

/**
 * Middleware opcional de autenticación
 * No falla si no hay token, pero carga el usuario si existe
 */
export const optionalAuth = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      next();
      return;
    }

    const token = authHeader.substring(7);
    const payload = AuthService.verifyAccessToken(token);
    
    const user = await User.findById(payload.userId).select('+isActive');
    
    if (user && user.isActive) {
      req.user = user;
      req.tokenPayload = payload;
    }
    
    next();
  } catch (error) {
    // En autenticación opcional, continuamos aunque el token sea inválido
    next();
  }
};
