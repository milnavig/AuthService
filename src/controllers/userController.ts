import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcrypt';
import qrcode from 'qrcode';
import speakeasy from 'speakeasy';
import jwt, { Secret, JwtPayload } from 'jsonwebtoken';
import { validationResult } from 'express-validator';
import User from '../models/User';
import jwtUtils from '../utils/jwtUtils';
import APIError from '../error/APIError';

class UserController {
  async register(req: Request, res: Response, next: NextFunction) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return next(APIError.badRequest('Invalid data in the inputs!'));
      }

      const { email, password } = req.body;

      if (!email || !password) {
        return next(APIError.badRequest('Incorrect email or password!'));
      }

      const candidate = await User.findOne({ email });
      if (candidate) {
        return next(APIError.badRequest('Such user already exists!'));
      }

      const hashed_password = await bcrypt.hash(password, 5); // hash password 5 times

      const user = new User({ email, password: hashed_password });
      const created_user = await user.save();

      const token = jwtUtils.generate_jwt(created_user._id);
      const { access_token, refresh_token } = token;
      const expiration_time = 30 * 24 * 60 * 60 * 1000; // 30 days
      const expiration_date = new Date(Date.now() + expiration_time); // Expiry in 30 days
      await jwtUtils.save_token(created_user._id, refresh_token, expiration_date);
      res.cookie('refreshToken', refresh_token, { maxAge: expiration_time, httpOnly: true }); // Secure?????

      res.status(201).json({created_user, access_token, refresh_token});
    } catch (error) {
      if (error instanceof Error) {
        // Handle the error
        return next(APIError.internal(error.message));
      }
    }
  }

  async login(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user) {
        return next(APIError.badRequest('There is no such user!'));
      }

      let comparePassword = bcrypt.compareSync(password, user.password);
      if (!comparePassword) {
        return next(APIError.badRequest('Incorrect password!'));
      }

      const token = jwtUtils.generate_jwt(user._id);
      const { access_token, refresh_token } = token;
      const expiration_time = 30 * 24 * 60 * 60 * 1000; // 30 days
      const expiration_date = new Date(Date.now() + expiration_time); // Expiry in 30 days
      await jwtUtils.save_token(user._id, refresh_token, expiration_date);
      res.cookie('refreshToken', refresh_token, { maxAge: expiration_time, httpOnly: true });

      return res.json({ access_token, refresh_token });
    } catch (error) {
      if (error instanceof Error) {
        // Handle the error
        return next(APIError.internal(error.message));
      }
    }
  }

  async enable_2fa(req: Request, res: Response, next: NextFunction) { 
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user) {
        return next(APIError.badRequest('There is no such user!'));
      }

      let comparePassword = bcrypt.compareSync(password, user.password);
      if (!comparePassword) {
        return next(APIError.badRequest('Incorrect password!'));
      }

      // Generate a new secret key for the user
      const secret = speakeasy.generateSecret({ length: 20 });
    
      // Store the secret.key securely in your database, associated with the user's account
      // add a tiemstamp to secret key
      user.secretKey = await bcrypt.hash(secret.base32, 5);

      await user.save();

      // Generate a URL for the user to scan with their authenticator app
      const otpauthUrl = speakeasy.otpauthURL({
        secret: secret.ascii,
        label: 'AuthService',
        issuer: 'AuthService',
      });

      // Generate a QR code containing the OTP authentication URL
      qrcode.toDataURL(otpauthUrl, (err, imageUrl) => {
        if (err) {
          return next(APIError.internal('Error generating QR code!'));
        }

        // Return the QR code image URL to the client
        return res.json({ userId: user._id, qrcodeUrl: imageUrl });
      });
    } catch (error) {
      if (error instanceof Error) {
        // Handle the error
        return next(APIError.internal(error.message));
      }
    }
  }

  async login_2fa(req: Request, res: Response, next: NextFunction) { 
    try {
      const { userId, otpAuthUrl } = req.body;

      // Parse the OTP authentication URL
      const parsedUrl = new URL(otpAuthUrl);

      // Extract the secret key from the query parameters
      const queryParams = new URLSearchParams(parsedUrl.search);
      const secretKey = queryParams.get('secret') ?? '';

      const user = await User.findOne({ _id: userId });

      if (!user) {
        return next(APIError.badRequest('There is no such user!'));
      }

      let compareSecrets = bcrypt.compareSync(secretKey, user.secretKey);
      if (!compareSecrets) {
        return next(APIError.badRequest('Incorrect one-time code!'));
      }

      const token = jwtUtils.generate_jwt(user._id);
      const { access_token, refresh_token } = token;
      const expiration_time = 30 * 24 * 60 * 60 * 1000; // 30 days
      const expiration_date = new Date(Date.now() + expiration_time); // Expiry in 30 days
      await jwtUtils.save_token(user._id, refresh_token, expiration_date);
      res.cookie('refreshToken', refresh_token, { maxAge: expiration_time, httpOnly: true });

      user.secretKey = '';
      await user.save();

      return res.json({access_token, refresh_token});
    } catch (error) {
      if (error instanceof Error) {
        // Handle the error
        return next(APIError.internal(error.message));
      }
    }
  }

  async logout(req: Request, res: Response, next: NextFunction) {
    try {
      const { refreshToken } = req.cookies;

      if (!refreshToken) {
        return next(APIError.unauthorized('No refresh token!'));
      }

      await jwtUtils.delete_token(refreshToken);
      res.clearCookie('refreshToken');
      
      return res.json({message: 'User was logged out!'});
    } catch (error) {
      if (error instanceof Error) {
        // Handle the error
        return next(APIError.internal(error.message));
      }
    }
  }

  async refresh(req: Request, res: Response, next: NextFunction) {
    try {
      const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY as Secret;

      const { refreshToken } = req.cookies;

      if (!refreshToken) {
        return next(APIError.unauthorized('No refresh token!'));
      }
      
      const userData = jwt.verify(refreshToken, REFRESH_SECRET_KEY) as JwtPayload;

      const tokenFromDB = await jwtUtils.get_token(refreshToken);

      if (!userData || !tokenFromDB) {
        return next(APIError.unauthorized('User is not authorized!'));
      }

      const user = await User.findOne({ _id: userData.userId });

      if (!user) {
        return next(APIError.badRequest('There is no such user!'));
      }
      
      const token = jwtUtils.generate_jwt(user._id);
      const { access_token, refresh_token } = token;
      const expiration_time = 30 * 24 * 60 * 60 * 1000; // 30 days
      const expiration_date = new Date(Date.now() + expiration_time); // Expiry in 30 days
      await jwtUtils.save_token(user._id, refresh_token, expiration_date);
      res.cookie('refreshToken', refresh_token, { maxAge: expiration_time, httpOnly: true });

      return res.json({access_token, refresh_token});
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        return next(APIError.internal('Access token has expired!'));
      } else if (error instanceof Error) {
        // Handle the error
        return next(APIError.internal(error.message));
      }
    }
  }

  async update(req: Request, res: Response, next: NextFunction) {
    try {
      const user_id = req.user?.userId;
      const { old_password, new_password } = req.body;

      // Find the user by ID
      const user = await User.findById(user_id);
  
      if (!user) {
        return next(APIError.notFound('User not found'));
      }
  
      // Compare old password
      const isPasswordMatch = await bcrypt.compare(old_password, user.password);
  
      if (!isPasswordMatch) {
        return next(APIError.unauthorized('Old password is incorrect'));
      }
  
      // Hash and update the new password
      const hashedNewPassword = await bcrypt.hash(new_password, 5);
      user.password = hashedNewPassword;
  
      await user.save();
  
      return res.status(200).json({ message: 'Password changed successfully' });
    } catch (error) {
      if (error instanceof Error) {
        // Handle the error
        return next(APIError.internal(error.message));
      }
    }
  }

  async generate_code(req: Request, res: Response, next: NextFunction) { // generate QR code for user
    try {
      const { userId } = req.params;
  
      // Generate a new secret key for the user
      const secret = speakeasy.generateSecret({ length: 20 });
  
      // Store the secret.key securely in your database, associated with the user's account
  
      // Generate a URL for the user to scan with their authenticator app
      const otpauthUrl = speakeasy.otpauthURL({
        secret: secret.ascii,
        label: 'AuthService',
        issuer: 'AuthService',
      });
  
      // Generate a QR code containing the OTP authentication URL
      qrcode.toDataURL(otpauthUrl, (err, imageUrl) => {
        if (err) {
          return next(APIError.internal('Error generating QR code'));
        }
  
        // Return the QR code image URL to the client
        return res.json({ imageUrl });
      });
    } catch (error) {
      console.error('Error generating QR code:', error);
      if (error instanceof Error) {
        // Handle the error
        return next(APIError.internal(error.message));
      }
    }
  }

  async get_protected_resource(req: Request, res: Response, next: NextFunction) { 

  }
}

export default new UserController();