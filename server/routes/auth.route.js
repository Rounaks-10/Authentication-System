import express from 'express'
import { isAuthenticated, login, logout, register, resetPassword, sendResetotp, sendVerifyOtp, verifyEmail } from '../controllers/auth.controller.js';
import {loginWithPin, resetPin, sendPinResetOtp, setPin} from '../controllers/pin.controller.js'
import userAuth from '../middleware/userAuth.js';


const authRouter = express.Router();

authRouter.post('/register',register);
authRouter.post('/login',login);
authRouter.post('/logout',logout);
authRouter.post('/send-verify-otp',userAuth,sendVerifyOtp);
authRouter.post('/verify-account',userAuth,verifyEmail);
authRouter.post('/is-auth',userAuth,isAuthenticated);
authRouter.post('/send-reset-otp',sendResetotp);
authRouter.post('/reset-password',resetPassword);
authRouter.post('/set-pin', setPin);
authRouter.post('/login-pin', loginWithPin);
authRouter.post('/send-pin-reset-otp', sendPinResetOtp);
authRouter.post('/reset-pin', resetPin);

export default authRouter;
