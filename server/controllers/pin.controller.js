import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/user.model.js';
import transporter from '../config/nodeMailer.js';

export const setPin = async (req, res) => {
    try {
        const { userId, pin } = req.body;

        if (!userId || !pin) {
            return res.json({ success: false, message: "Missing details" });
        }

        if (pin.length < 4 || pin.length > 6) {
            return res.json({ success: false, message: "PIN should be 4 to 6 digits" });
        }

        const user = await userModel.findById(userId);
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        const hashedPin = await bcrypt.hash(pin, 10);
        user.pin = hashedPin;
        await user.save();

        return res.json({ success: true, message: "PIN set successfully" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

export const loginWithPin = async (req, res) => {
    try {
        const { email, pin } = req.body;

        if (!email || !pin) {
            return res.json({ success: false, message: "Email and PIN required" });
        }

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (!user.pin) {
            return res.json({ success: false, message: "PIN not set for this account" });
        }

        const isMatch = await bcrypt.compare(pin, user.pin);
        if (!isMatch) {
            return res.json({ success: false, message: "Invalid PIN" });
        }

        // Generate JWT token for session
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ success: true, message: "Logged in successfully with PIN" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

export const sendPinResetOtp = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.json({ success: false, message: "Email is required" });
        }

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 60 * 60 * 1000; // 1 hour expiry
        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "PIN Reset OTP",
            text: `Your OTP to reset your PIN is ${otp}. It is valid for 1 hour.`,
        };
        await transporter.sendMail(mailOption);

        return res.json({ success: true, message: "OTP sent to registered email" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

export const resetPin = async (req, res) => {
    try {
        const { email, otp, newPin } = req.body;

        if (!email || !otp || !newPin) {
            return res.json({ success: false, message: "Missing details" });
        }

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (user.resetOtp !== otp) {
            return res.json({ success: false, message: "Invalid OTP" });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "OTP expired" });
        }

        const hashedPin = await bcrypt.hash(newPin, 10);
        user.pin = hashedPin;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;
        await user.save();

        return res.json({ success: true, message: "PIN reset successfully" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};
