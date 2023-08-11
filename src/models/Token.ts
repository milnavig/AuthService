import mongoose, { Document, Schema } from 'mongoose';

// Define the schema for the Token model
export interface IToken extends Document {
  userId: mongoose.Schema.Types.ObjectId;
  refreshToken: string;
  expirationDate: Date;
  revoked: boolean;
}

const tokenSchema = new Schema<IToken>(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    refreshToken: { type: String, required: true },
    expirationDate: { type: Date, required: true },
    //revoked: { type: Boolean, required: true, default: false },
  },
  { timestamps: true } // Adds createdAt and updatedAt fields
);

// Create the Token model
const Token = mongoose.model<IToken>('Token', tokenSchema);

export default Token;