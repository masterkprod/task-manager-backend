import mongoose from 'mongoose';
import { config } from './config';

/**
 * Configuración y conexión a MongoDB
 */
export const connectDatabase = async (): Promise<void> => {
  try {
    const mongoUri = config.mongodbUri;
    
    await mongoose.connect(mongoUri);
    
    console.log('✅ Conectado a MongoDB exitosamente');
    
    // Configurar eventos de conexión
    mongoose.connection.on('error', (error) => {
      console.error('❌ Error de conexión a MongoDB:', error);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.log('⚠️ Desconectado de MongoDB');
    });
    
    // Manejar cierre graceful
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('🔒 Conexión a MongoDB cerrada por terminación de aplicación');
      process.exit(0);
    });
    
  } catch (error) {
    console.error('❌ Error al conectar a MongoDB:', error);
    process.exit(1);
  }
};
