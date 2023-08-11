// middleware for checking authentification 

import { Request, Response, NextFunction } from 'express';
import jwt, { Secret, JwtPayload } from 'jsonwebtoken';
import APIError from '../error/APIError';
import Token, { IToken } from '../models/Token';

// Extend the Request type to include the 'user' property
declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload; // Attach the JwtPayload type to 'user'
    }
  }
}

export default async function(req: Request, res: Response, next: NextFunction) {
  try {
    const SECRET_KEY = process.env.SECRET_KEY as Secret;

    const token = req.headers?.authorization?.split(' ')[1]; // Bearer 1234
    if (!token) {
      return next(APIError.unauthorized('User isn\'t authorized!'));
    }

    const decoded_token = jwt.verify(token, SECRET_KEY) as JwtPayload;

    const refreshToken: IToken | null = await Token.findOne({ userId: decoded_token.userId });

    if (!refreshToken) {
      return next(APIError.unauthorized('User isn\'t authorized!'));
    }

    req.user = decoded_token;
    next();
  } catch(error) {
    if (error instanceof Error) {
      // Handle the error
      return next(APIError.internal(error.message));
    }
  }
}