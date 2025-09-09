import jwt from 'jsonwebtoken';
import { config } from '../config/config';
import { IUser } from '../models/User';

/**
 * Interfaz para el payload del JWT
 */
export interface JWTPayload {
  userId: string;
  email: string;
  role: string;
}

/**
 * Interfaz para los tokens generados
 */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

/**
 * Servicio de autenticación JWT
 */
export class AuthService {
  /**
   * Genera un par de tokens (access + refresh)
   */
  static generateTokenPair(user: IUser): TokenPair {
    const payload: JWTPayload = {
      userId: user._id,
      email: user.email,
      role: user.role,
    };

    const accessToken = jwt.sign(
      payload,
      config.jwt.accessSecret,
      { 
        expiresIn: config.jwt.accessExpiresIn,
        issuer: 'task-manager-api',
        audience: 'task-manager-client',
      } as jwt.SignOptions
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      config.jwt.refreshSecret,
      { 
        expiresIn: config.jwt.refreshExpiresIn,
        issuer: 'task-manager-api',
        audience: 'task-manager-client',
      } as jwt.SignOptions
    );

    return { accessToken, refreshToken };
  }

  /**
   * Verifica un access token
   */
  static verifyAccessToken(token: string): JWTPayload {
    try {
      const decoded = jwt.verify(token, config.jwt.accessSecret, {
        issuer: 'task-manager-api',
        audience: 'task-manager-client',
      }) as JWTPayload;
      
      return decoded;
    } catch (error) {
      throw new Error('Token de acceso inválido o expirado');
    }
  }

  /**
   * Verifica un refresh token
   */
  static verifyRefreshToken(token: string): { userId: string } {
    try {
      const decoded = jwt.verify(token, config.jwt.refreshSecret, {
        issuer: 'task-manager-api',
        audience: 'task-manager-client',
      }) as { userId: string };
      
      return decoded;
    } catch (error) {
      throw new Error('Token de actualización inválido o expirado');
    }
  }

  /**
   * Genera un nuevo access token usando un refresh token válido
   */
  static refreshAccessToken(refreshToken: string, user: IUser): string {
    // Verificar el refresh token
    this.verifyRefreshToken(refreshToken);

    // Generar nuevo access token
    const payload: JWTPayload = {
      userId: user._id,
      email: user.email,
      role: user.role,
    };

    return jwt.sign(
      payload,
      config.jwt.accessSecret,
      { 
        expiresIn: config.jwt.accessExpiresIn,
        issuer: 'task-manager-api',
        audience: 'task-manager-client',
      } as jwt.SignOptions
    );
  }

  /**
   * Decodifica un token sin verificar (para debugging)
   */
  static decodeToken(token: string): any {
    return jwt.decode(token);
  }
}
