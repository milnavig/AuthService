import express from 'express';

import authController from '../controllers/userController';
import authMiddleware from '../middleware/authMiddleware';

import { body } from 'express-validator';

const router = express.Router();

router.post('/register', body('email').isEmail(), body('password').isLength({min: 3, max: 32}), authController.register);
router.post('/login', authController.login);
router.post('/enable-2fa', authController.enable_2fa);
router.post('/login-2fa', authController.login_2fa);
router.post('/logout', authController.logout);
router.get('/refresh', authMiddleware, authController.refresh);
router.post('/update', authMiddleware, authController.update); // update password
router.get('/generate-qr-code/:userId', authController.generate_code);

export default router;