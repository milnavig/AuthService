import mongoose from 'mongoose';

export async function connectToDatabase() {
  try {
    await mongoose.connect(`mongodb://${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`, {});
    console.log('Connected to database');
  } catch (error) {
    console.error('Database connection error:', error);
  }
}