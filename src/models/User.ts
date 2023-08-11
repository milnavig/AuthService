import mongoose, { Document, Schema } from 'mongoose';

export interface IUser extends Document {
  email: string;
  password: string;
  secretKey: string;
}

const userSchema = new Schema<IUser>(
  {
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    // Store the secret key for 2FA
    secretKey: { type: String, required: false },
  }, { 
    timestamps: true 
  }
);

const User = mongoose.model<IUser>('User', userSchema);

export default User;