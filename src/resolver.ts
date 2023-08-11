import jwt, { Secret, JwtPayload } from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import qrcode from 'qrcode';
import speakeasy from 'speakeasy';
import IUserInput from './interfaces/IUserInput';
import ICodeInput from './interfaces/ICodeInput';
import IUpdateInput from './interfaces/IUpdateInput';
import User from './models/User';
import jwtUtils from './utils/jwtUtils';
import APIError from './error/APIError';

export const resolvers = {
  Query: {
    logout: async (parent: any, input: any, contextValue: any, info: any) => {
      try {
        const { refreshToken } = contextValue.req.cookies;
  
        if (!refreshToken) {
          throw APIError.unauthorized('No refresh token!');
        }
  
        await jwtUtils.delete_token(refreshToken);
        contextValue.res.clearCookie('refreshToken');
        
        return {message: 'User was logged out!'};
      } catch (error) {
        if (error instanceof Error) {
          // Handle the error
          throw APIError.internal(error.message);
        }
      }
    },
    refresh: async (parent: any, input: any, contextValue: any, info: any) => {
      try {
        const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY as Secret;
  
        const { refreshToken } = contextValue.req.cookies;
  
        if (!refreshToken) {
          throw APIError.unauthorized('No refresh token!');
        }
        
        const userData = jwt.verify(refreshToken, REFRESH_SECRET_KEY) as JwtPayload;
  
        const tokenFromDB = await jwtUtils.get_token(refreshToken);
  
        if (!userData || !tokenFromDB) {
          throw APIError.unauthorized('User is not authorized!');
        }
  
        const user = await User.findOne({ _id: userData.userId });
  
        if (!user) {
          throw APIError.badRequest('There is no such user!');
        }
        
        const token = jwtUtils.generate_jwt(user._id);
        const { access_token, refresh_token } = token;
        const expiration_time = 30 * 24 * 60 * 60 * 1000; // 30 days
        const expiration_date = new Date(Date.now() + expiration_time); // Expiry in 30 days
        await jwtUtils.save_token(user._id, refresh_token, expiration_date);
        contextValue.res.cookie('refreshToken', refresh_token, { maxAge: expiration_time, httpOnly: true });
  
        return {access_token, refresh_token};
      } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
          throw APIError.internal('Access token has expired!');
        } else if (error instanceof Error) {
          // Handle the error
          throw (APIError.internal(error.message));
        }
      }
    },
  },
  Mutation: {
    register: async (parent: any, { input }: { input: IUserInput }, contextValue: any, info: any) => {
      try {
        // add validation

        const { email, password } = input;
  
        if (!email || !password) {
          throw APIError.badRequest('Incorrect email or password!');
        }
  
        const candidate = await User.findOne({ email });
        if (candidate) {
          throw APIError.badRequest('Such user already exists!');
        }
  
        const hashed_password = await bcrypt.hash(password, 5); // hash password 5 times
  
        const user = new User({ email, password: hashed_password });
        const created_user = await user.save();
  
        return { message: `User was created successfully! User id: ${created_user._id}` };
      } catch (error) {
        if (error instanceof Error) {
          // Handle the error
          throw APIError.internal(error.message);
        }
      }
    },
    enable_2fa: async (parent: any, { input }: { input: IUserInput }, contextValue: any, info: any) => {
      try {
        const { email, password } = input;
        const user = await User.findOne({ email });
        if (!user) {
          throw APIError.badRequest('There is no such user!');
        }

        let comparePassword = bcrypt.compareSync(password, user.password);
        if (!comparePassword) {
          throw APIError.badRequest('Incorrect password!');
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
        try {
          const imageUrl = await qrcode.toDataURL(otpauthUrl);
        
          return { userId: user._id.toString(), qrcodeUrl: imageUrl };
        } catch (err) {
          throw APIError.internal('Error generating QR code!');
        }
      } catch (error) {
        if (error instanceof Error) {
          // Handle the error
          throw APIError.internal(error.message);
        }
      }
    },
    login_2fa: async (parent: any, { input }: { input: ICodeInput }, contextValue: any, info: any) => {
      try {
        const { userId, otpAuthUrl } = input;

        // Parse the OTP authentication URL
        const parsedUrl = new URL(otpAuthUrl);

        // Extract the secret key from the query parameters
        const queryParams = new URLSearchParams(parsedUrl.search);
        const secretKey = queryParams.get('secret') ?? '';

        const user = await User.findOne({ _id: userId });

        if (!user) {
          throw APIError.badRequest('There is no such user!');
        }

        let compareSecrets = bcrypt.compareSync(secretKey, user.secretKey);
        if (!compareSecrets) {
          throw APIError.badRequest('Incorrect one-time code!');
        }

        const token = jwtUtils.generate_jwt(user._id);
        const { access_token, refresh_token } = token;
        const expiration_time = 30 * 24 * 60 * 60 * 1000; // 30 days
        const expiration_date = new Date(Date.now() + expiration_time); // Expiry in 30 days
        await jwtUtils.save_token(user._id, refresh_token, expiration_date);

        user.secretKey = '';
        await user.save();

        contextValue?.res?.cookie('refreshToken', refresh_token, { maxAge: expiration_time, httpOnly: true }); // Secure?????

        return { access_token, refresh_token };
      } catch (error) {
        if (error instanceof Error) {
          // Handle the error
          throw APIError.internal(error.message);
        }
      }
    },
    update: async (parent: any, { input }: { input: IUpdateInput }, contextValue: any, info: any) => {
      try {
        const user_id = contextValue.req.user?.userId;

        if (!user_id) {
          throw APIError.notFound('User is not logged in! Maybe access token is expired');
        }

        const { old_password, new_password } = input;
  
        // Find the user by ID
        const user = await User.findById(user_id);
    
        if (!user) {
          throw APIError.notFound('User not found');
        }
    
        // Compare old password
        const isPasswordMatch = await bcrypt.compare(old_password, user.password);
    
        if (!isPasswordMatch) {
          throw APIError.unauthorized('Old password is incorrect');
        }
    
        // Hash and update the new password
        const hashedNewPassword = await bcrypt.hash(new_password, 5);
        user.password = hashedNewPassword;
    
        await user.save();
    
        return { message: 'Password changed successfully' };
      } catch (error) {
        if (error instanceof Error) {
          // Handle the error
          throw APIError.internal(error.message);
        }
      }
    }
  }
}