// middleware for handling errors

import { Request, Response, NextFunction } from 'express';
import APIError from './../error/APIError';

export default function(err: Error, req: Request, res: Response, next: NextFunction) {
  if (err instanceof APIError) {
    console.error(err.message);
    return res.status(err.status).json({ message: err.message });
  }
  console.error(err.message);
  return res.status(500).json({message: "Unknown error!"});
}