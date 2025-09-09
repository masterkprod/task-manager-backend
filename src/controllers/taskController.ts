import { Request, Response } from 'express';
import { Task } from '../models/Task';
import { User } from '../models/User';

/**
 * Controlador de tareas
 */
export class TaskController {
  /**
   * Crear nueva tarea
   */
  static async createTask(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Usuario no autenticado',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const { title, description, status, priority, dueDate } = req.body;

      const task = new Task({
        title,
        description,
        status: status || 'pending',
        priority: priority || 'medium',
        dueDate: dueDate ? new Date(dueDate) : undefined,
        userId: req.user._id,
      });

      await task.save();
      await task.populate('userId', 'name email');

      res.status(201).json({
        success: true,
        message: 'Tarea creada exitosamente',
        data: {
          task,
        },
      });
    } catch (error) {
      console.error('Error al crear tarea:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Obtener tareas del usuario autenticado o todas si es admin
   */
  static async getTasks(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Usuario no autenticado',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const skip = (page - 1) * limit;

      // Construir filtros
      const filters: any = {};
      
      // Si no es admin, solo mostrar sus propias tareas
      if (req.user.role !== 'admin') {
        filters.userId = req.user._id;
      } else {
        // Admin puede filtrar por usuario específico
        if (req.query.userId) {
          filters.userId = req.query.userId;
        }
      }

      // Filtros adicionales
      if (req.query.status) {
        filters.status = req.query.status;
      }
      if (req.query.priority) {
        filters.priority = req.query.priority;
      }

      // Filtro por fecha de vencimiento
      if (req.query.dueDate) {
        const dueDate = new Date(req.query.dueDate as string);
        filters.dueDate = { $lte: dueDate };
      }

      // Búsqueda por texto
      if (req.query.search) {
        const searchRegex = new RegExp(req.query.search as string, 'i');
        filters.$or = [
          { title: searchRegex },
          { description: searchRegex },
        ];
      }

      // Buscar tareas
      const tasks = await Task.find(filters)
        .populate('userId', 'name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit);

      // Contar total
      const total = await Task.countDocuments(filters);

      res.json({
        success: true,
        data: {
          tasks,
          pagination: {
            page,
            limit,
            total,
            pages: Math.ceil(total / limit),
          },
        },
      });
    } catch (error) {
      console.error('Error al obtener tareas:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Obtener tarea por ID
   */
  static async getTaskById(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Usuario no autenticado',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const { id } = req.params;

      const task = await Task.findById(id).populate('userId', 'name email');
      if (!task) {
        res.status(404).json({
          success: false,
          message: 'Tarea no encontrada',
          code: 'TASK_NOT_FOUND',
        });
        return;
      }

      // Verificar permisos: solo el propietario o admin puede ver la tarea
      const taskUserId = typeof task.userId === 'string' ? task.userId : (task.userId as any)._id.toString();
      if (req.user.role !== 'admin' && taskUserId !== req.user._id.toString()) {
        res.status(403).json({
          success: false,
          message: 'No tienes permisos para ver esta tarea',
          code: 'INSUFFICIENT_PERMISSIONS',
        });
        return;
      }

      res.json({
        success: true,
        data: {
          task,
        },
      });
    } catch (error) {
      console.error('Error al obtener tarea:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Actualizar tarea
   */
  static async updateTask(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Usuario no autenticado',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const { id } = req.params;
      const { title, description, status, priority, dueDate } = req.body;

      // Buscar la tarea
      const task = await Task.findById(id);
      if (!task) {
        res.status(404).json({
          success: false,
          message: 'Tarea no encontrada',
          code: 'TASK_NOT_FOUND',
        });
        return;
      }

      // Verificar permisos: solo el propietario o admin puede actualizar
      if (req.user.role !== 'admin' && task.userId.toString() !== req.user._id.toString()) {
        res.status(403).json({
          success: false,
          message: 'No tienes permisos para actualizar esta tarea',
          code: 'INSUFFICIENT_PERMISSIONS',
        });
        return;
      }

      // Actualizar tarea
      const updatedTask = await Task.findByIdAndUpdate(
        id,
        {
          ...(title && { title }),
          ...(description && { description }),
          ...(status && { status }),
          ...(priority && { priority }),
          ...(dueDate && { dueDate: new Date(dueDate) }),
        },
        { 
          new: true, 
          runValidators: true 
        }
      ).populate('userId', 'name email');

      res.json({
        success: true,
        message: 'Tarea actualizada exitosamente',
        data: {
          task: updatedTask,
        },
      });
    } catch (error) {
      console.error('Error al actualizar tarea:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Eliminar tarea
   */
  static async deleteTask(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Usuario no autenticado',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const { id } = req.params;

      // Buscar la tarea
      const task = await Task.findById(id);
      if (!task) {
        res.status(404).json({
          success: false,
          message: 'Tarea no encontrada',
          code: 'TASK_NOT_FOUND',
        });
        return;
      }

      // Verificar permisos: solo el propietario o admin puede eliminar
      if (req.user.role !== 'admin' && task.userId.toString() !== req.user._id.toString()) {
        res.status(403).json({
          success: false,
          message: 'No tienes permisos para eliminar esta tarea',
          code: 'INSUFFICIENT_PERMISSIONS',
        });
        return;
      }

      await Task.findByIdAndDelete(id);

      res.json({
        success: true,
        message: 'Tarea eliminada exitosamente',
      });
    } catch (error) {
      console.error('Error al eliminar tarea:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }

  /**
   * Obtener estadísticas de tareas
   */
  static async getTaskStats(req: Request, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'Usuario no autenticado',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const filters: any = {};
      
      // Si no es admin, solo estadísticas de sus tareas
      if (req.user.role !== 'admin') {
        filters.userId = req.user._id;
      } else {
        // Admin puede filtrar por usuario específico
        if (req.query.userId) {
          filters.userId = req.query.userId;
        }
      }

      // Obtener estadísticas
      const [
        totalTasks,
        pendingTasks,
        inProgressTasks,
        completedTasks,
        highPriorityTasks,
        overdueTasks,
      ] = await Promise.all([
        Task.countDocuments(filters),
        Task.countDocuments({ ...filters, status: 'pending' }),
        Task.countDocuments({ ...filters, status: 'in-progress' }),
        Task.countDocuments({ ...filters, status: 'completed' }),
        Task.countDocuments({ ...filters, priority: 'high' }),
        Task.countDocuments({ 
          ...filters, 
          dueDate: { $lt: new Date() },
          status: { $ne: 'completed' }
        }),
      ]);

      res.json({
        success: true,
        data: {
          stats: {
            total: totalTasks,
            pending: pendingTasks,
            inProgress: inProgressTasks,
            completed: completedTasks,
            highPriority: highPriorityTasks,
            overdue: overdueTasks,
            completionRate: totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 100) : 0,
          },
        },
      });
    } catch (error) {
      console.error('Error al obtener estadísticas:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        code: 'INTERNAL_ERROR',
      });
    }
  }
}
