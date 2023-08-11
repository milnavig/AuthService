import express from 'express';

import authController from '../controllers/userController';
import authMiddleware from '../middleware/authMiddleware'; // middleware for checking authentification 

import { body } from 'express-validator';

const router = express.Router();

// route for registration of the new user
router.post('/register', body('email').isEmail(), body('password').isLength({min: 3, max: 32}), authController.register);
// route for login
router.post('/login', authController.login);
// route for passing the first step of two-factor authorization
router.post('/enable-2fa', authController.enable_2fa);
// route for passing the second step of two-factor authorization
router.post('/login-2fa', authController.login_2fa);
// route for logout
router.post('/logout', authController.logout);
// route for refreshing of JWT tokens
router.get('/refresh', authMiddleware, authController.refresh);
// route for updating a password
router.post('/update', authMiddleware, authController.update);

export default router;