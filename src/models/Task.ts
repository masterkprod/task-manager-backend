import mongoose, { Document, Schema } from 'mongoose';

/**
 * Interfaz para el documento de Tarea
 */
export interface ITask extends Document {
  _id: string;
  title: string;
  description: string;
  status: 'pending' | 'in-progress' | 'completed';
  priority: 'low' | 'medium' | 'high';
  dueDate?: Date;
  userId: string;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Esquema de Tarea
 */
const taskSchema = new Schema<ITask>({
  title: {
    type: String,
    required: [true, 'El título es requerido'],
    trim: true,
    minlength: [1, 'El título debe tener al menos 1 carácter'],
    maxlength: [100, 'El título no puede exceder 100 caracteres'],
  },
  description: {
    type: String,
    required: [true, 'La descripción es requerida'],
    trim: true,
    minlength: [1, 'La descripción debe tener al menos 1 carácter'],
    maxlength: [500, 'La descripción no puede exceder 500 caracteres'],
  },
  status: {
    type: String,
    enum: {
      values: ['pending', 'in-progress', 'completed'],
      message: 'El estado debe ser "pending", "in-progress" o "completed"',
    },
    default: 'pending',
  },
  priority: {
    type: String,
    enum: {
      values: ['low', 'medium', 'high'],
      message: 'La prioridad debe ser "low", "medium" o "high"',
    },
    default: 'medium',
  },
  dueDate: {
    type: Date,
    validate: {
      validator: function(value: Date) {
        // La fecha de vencimiento debe ser en el futuro
        return !value || value > new Date();
      },
      message: 'La fecha de vencimiento debe ser en el futuro',
    },
  },
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'El ID del usuario es requerido'],
  } as any,
}, {
  timestamps: true,
});

/**
 * Índices para optimizar consultas
 */
taskSchema.index({ userId: 1 });
taskSchema.index({ status: 1 });
taskSchema.index({ priority: 1 });
taskSchema.index({ dueDate: 1 });
taskSchema.index({ createdAt: -1 });

/**
 * Índice compuesto para consultas frecuentes
 */
taskSchema.index({ userId: 1, status: 1 });
taskSchema.index({ userId: 1, priority: 1 });

export const Task = mongoose.model<ITask>('Task', taskSchema);
