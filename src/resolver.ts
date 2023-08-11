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

import authController from './controllers/graphql/userController';

// resolvers for Apollo Server
export const resolvers = {
  Query: {
    // logout resolver
    logout: authController.logout,
    // resolver for refreshing access and refresh tokens
    refresh: authController.refresh,
    get_protected_resource: authController.get_protected_resource,
  },
  Mutation: {
    // resolver for registration of a new user
    register: authController.register,
    // resolver for the first step of authentification
    // it checks email and password for correctness and returns QR-code
    enable_2fa: authController.enable_2fa,
    // resolver for the second step of authentification
    // it checks the correctness of the one-time code and returns two tokens
    // namely access and refresh tokens
    login_2fa: authController.login_2fa,
    // resolver for password update
    update: authController.update
  }
}