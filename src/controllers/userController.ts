import { Request, Response } from 'express';
import { User } from '../models/User';
import { AuthService } from '../services/authService';

/**
 * Controlador de usuarios
 */
export class UserController {
  /**
   * Actualizar perfil del usuario autenticado
   */
  static async updateProfile(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Usuario no autenticado',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const { name, email } = req.body;
      const userId = req.user._id;

      // Verificar si el email ya está en uso por otro usuario
      if (email && email !== req.user.email) {
        const existingUser = await User.findOne({ 
          email, 
          _id: { $ne: userId } 
        });
        
        if (existingUser) {
          res.status(409).json({
            success: false,
            message: 'Ya existe un usuario con este email',
            code: 'EMAIL_IN_USE',
          });
          return;
        }
      }

      // Actualizar usuario
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { 
          ...(name && { name }),
          ...(email && { email }),
        },
        { 
          new: true, 
          runValidators: true 
        }
      );

      if (!updatedUser) {
        res.status(404).json({
          success: false,
          message: 'Usuario no encontrado',
          code: 'USER_NOT_FOUND',
        });
        return;
      }

      res.json({
        success: true,
        message: 'Perfil actualizado exitosamente',
        data: {
          user: updatedUser.toJSON(),
        },
      });
    } catch (error) {
      console.error('Error al actualizar perfil:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Cambiar contraseña del usuario autenticado
   */
  static async changePassword(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Usuario no autenticado',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const { currentPassword, newPassword } = req.body;
      const userId = req.user._id;

      // Buscar usuario con contraseña
      const user = await User.findById(userId).select('+password');
      if (!user) {
        res.status(404).json({
          success: false,
          message: 'Usuario no encontrado',
          code: 'USER_NOT_FOUND',
        });
        return;
      }

      // Verificar contraseña actual
      const isCurrentPasswordValid = await user.comparePassword(currentPassword);
      if (!isCurrentPasswordValid) {
        res.status(400).json({
          success: false,
          message: 'La contraseña actual es incorrecta',
          code: 'INVALID_CURRENT_PASSWORD',
        });
        return;
      }

      // Actualizar contraseña
      user.password = newPassword;
      await user.save();

      res.json({
        success: true,
        message: 'Contraseña actualizada exitosamente',
      });
    } catch (error) {
      console.error('Error al cambiar contraseña:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Desactivar cuenta del usuario autenticado
   */
  static async deactivateAccount(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Usuario no autenticado',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const userId = req.user._id;

      // Desactivar usuario
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { isActive: false },
        { new: true }
      );

      if (!updatedUser) {
        res.status(404).json({
          success: false,
          message: 'Usuario no encontrado',
          code: 'USER_NOT_FOUND',
        });
        return;
      }

      // Limpiar cookie de refresh token
      res.clearCookie('refreshToken');

      res.json({
        success: true,
        message: 'Cuenta desactivada exitosamente',
      });
    } catch (error) {
      console.error('Error al desactivar cuenta:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Obtener todos los usuarios (solo admin)
   */
  static async getAllUsers(req: Request, res: Response): Promise<void> {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const skip = (page - 1) * limit;

      // Construir filtros
      const filters: any = {};
      if (req.query.role) {
        filters.role = req.query.role;
      }
      if (req.query.isActive !== undefined) {
        filters.isActive = req.query.isActive === 'true';
      }

      // Buscar usuarios
      const users = await User.find(filters)
        .select('-__v')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit);

      // Contar total
      const total = await User.countDocuments(filters);

      res.json({
        success: true,
        data: {
          users,
          pagination: {
            page,
            limit,
            total,
            pages: Math.ceil(total / limit),
          },
        },
      });
    } catch (error) {
      console.error('Error al obtener usuarios:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Obtener usuario por ID (solo admin)
   */
  static async getUserById(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      const user = await User.findById(id);
      if (!user) {
        res.status(404).json({
          success: false,
          message: 'Usuario no encontrado',
          code: 'USER_NOT_FOUND',
        });
        return;
      }

      res.json({
        success: true,
        data: {
          user: user.toJSON(),
        },
      });
    } catch (error) {
      console.error('Error al obtener usuario:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Actualizar usuario por ID (solo admin)
   */
  static async updateUserById(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { name, email, role, isActive } = req.body;

      // Verificar si el email ya está en uso por otro usuario
      if (email) {
        const existingUser = await User.findOne({ 
          email, 
          _id: { $ne: id } 
        });
        
        if (existingUser) {
          res.status(409).json({
            success: false,
            message: 'Ya existe un usuario con este email',
            code: 'EMAIL_IN_USE',
          });
          return;
        }
      }

      // Actualizar usuario
      const updatedUser = await User.findByIdAndUpdate(
        id,
        { 
          ...(name && { name }),
          ...(email && { email }),
          ...(role && { role }),
          ...(isActive !== undefined && { isActive }),
        },
        { 
          new: true, 
          runValidators: true 
        }
      );

      if (!updatedUser) {
        res.status(404).json({
          success: false,
          message: 'Usuario no encontrado',
          code: 'USER_NOT_FOUND',
        });
        return;
      }

      res.json({
        success: true,
        message: 'Usuario actualizado exitosamente',
        data: {
          user: updatedUser.toJSON(),
        },
      });
    } catch (error) {
      console.error('Error al actualizar usuario:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Eliminar usuario por ID (solo admin)
   */
  static async deleteUserById(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      // No permitir eliminar el propio usuario
      if (req.user && req.user._id.toString() === id) {
        res.status(400).json({
          success: false,
          message: 'No puedes eliminar tu propia cuenta',
          code: 'CANNOT_DELETE_SELF',
        });
        return;
      }

      const deletedUser = await User.findByIdAndDelete(id);
      if (!deletedUser) {
        res.status(404).json({
          success: false,
          message: 'Usuario no encontrado',
          code: 'USER_NOT_FOUND',
        });
        return;
      }

      res.json({
        success: true,
        message: 'Usuario eliminado exitosamente',
      });
    } catch (error) {
      console.error('Error al eliminar usuario:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }
}
