import express from 'express';
import {
    register,
    login,
    logout,
} from '../Controllers/authControllers.js';
import { loginValidation, registerValidation } from '../validation/authValidation.js';

const authRouter = express.Router();

authRouter.post('/register', registerValidation, register);
authRouter.post('/login', loginValidation, login); 
authRouter.post('/logout', logout);

export default authRouter;
