const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Users = require('../model/Users');
const secret = process.env.JWT_SECRET;
const refreshSecret = process.env.JWT_REFRESH_TOKEN_SECRET;
const { OAuth2Client } = require('google-auth-library');
const { validationResult } = require('express-validator');
const sendResetToken = require('../service/forgetPassword');
const ResetCodes = require('../model/ResetCodes');

const authController = {
    login: async (request, response) => {
        const errors = validationResult(request);
        if (!errors.isEmpty()) {
            return response.status(401).json({ errors: errors.array() });
        }

        try {
            // These values are here because of express.json() middleware.
            const { username, password } = request.body;

            const data = await Users.findOne({ email: username });
            if (!data) {
                return response.status(401).json({ message: 'Invalid Credentials' });
            }

            const isMatch = await bcrypt.compare(password, data.password);
            if (!isMatch) {
                return response.status(401).json({ message: 'Invalid Credentials' });
            }

            const userDetails = {
                id: data._id,
                name: data.name,
                email: data.email,
                // This is the ensure backward compatibility
                role: data.role ? data.role : 'admin',
                adminId: data.adminId,
                credits: data.credits,
                subscription: data.subscription
            };
            const token = jwt.sign(userDetails, secret, { expiresIn: '1m' });
            const refreshToken = jwt.sign(userDetails,refreshSecret,{expiresIn:'7d'});

            response.cookie('jwtToken', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                path: '/',
                sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax'
            });

            response.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                path: '/',
                sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax'
            });

            response.json({ message: 'User authenticated', userDetails: userDetails });
        } catch (error) {
            console.log(error);
            response.status(500).json({ error: 'Internal server error ' });
        }
    },

    logout: (request, response) => {
        response.clearCookie('jwtToken');
        response.clearCookie('refreshToken');
        response.json({ message: 'User logged out successfully' });
    },

    isUserLoggedIn: async (request, response) => {
        const token = request.cookies.jwtToken;

        if (!token) {
            return response.status(401).json({ message: 'Unauthorized access' });
        }

        jwt.verify(token, secret, async (error, userDetails) => {
            if (error) {
                return response.status(401).json({ message: 'Unauthorized access' });
            } else {
                const data = await Users.findById({ _id: userDetails.id });
                return response.json({ userDetails: data });
            }
        });
    },

    register: async (request, response) => {
        try {
            const { username, password, name } = request.body;

            const data = await Users.findOne({ email: username });
            if (data) {
                return response.status(401)
                    .json({ message: 'User exist with the given email' });
            }

            const encryptedPassword = await bcrypt.hash(password, 10);

            const user = new Users({
                email: username,
                password: encryptedPassword,
                name: name,
                role: 'admin'
            });
            await user.save();
            const userDetails = {
                id: user._id,
                name: user.name,
                email: user.email,
                role: 'admin',
                credits: user.credits
            };
            const token = jwt.sign(userDetails, secret, { expiresIn: '1h' });

            response.cookie('jwtToken', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                path: '/',
                sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax'
            });
            response.json({ message: 'User authenticated', userDetails: userDetails });
        } catch (error) {
            console.log(error);
            return response.status(500).json({ message: 'Internal server error' });
        }
    },

    googleAuth: async (request, response) => {
        const { idToken } = request.body;
        if (!idToken) {
            return response.status(400).json({ message: 'Invalid request' });
        }

        try {
            const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
            const googleResponse = await googleClient.verifyIdToken({
                idToken: idToken,
                audience: process.env.GOOGLE_CLIENT_ID
            });

            const payload = googleResponse.getPayload();
            const { sub: googleId, email, name } = payload;

            let data = await Users.findOne({ email: email });
            if (!data) {
                data = new Users({
                    email: email,
                    name: name,
                    isGoogleUser: true,
                    googleId: googleId,
                    role: 'admin'
                });

                await data.save();
            }

            const user = {
                id: data._id ? data._id : googleId,
                username: email,
                name: name,
                role: data.role? data.role : 'admin',
                credits: data.credits
            };

            const token = jwt.sign(user, secret, { expiresIn: '1h' });
            const refreshToken = jwt.sign(user, refreshSecret, { expiresIn: '7d' });

            response.cookie('jwtToken', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                path: '/',
                sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax'
            });
            response.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                path: '/',
                sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax'
            });
            response.json({ message: 'User authenticated', userDetails: user });
        } catch (error) {
            console.log(error);
            return response.status(500).json({ error: 'Internal server error' });
        }
    },

    refreshToken: async(request, response) => {
        try{
            const refreshToken = request.cookies?.refreshToken;
            if(!refreshToken){
                return response.status(401).json({message:'No refresh token'});
            }
            const decoded = jwt.verify(refreshToken,refreshSecret);
            const data = await Users.findById({_id:decoded.id});
            const user = {
                id:data._id,
                uername:data.email,
                name:data.name,
                role:data.role? data.role:'admin',
                credits: data.credits,
                subscription: data.subscription
            };
            
            

            const newAccessToken = jwt.sign(user,secret,{expiresIn:'1h'});
            response.cookie('jwtToken', newAccessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                path: '/',
                sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax'
            });
            response.json({message:'Token refreshed', userDetails:user});
        }catch(error){
            console.log(error);
            response.status(500).json({message:'Internal server error'});
        }
    },

    sendResetPasswordToken : async (request, response) => {
        const {email} = request.body;
        try{
            const data = await Users.findOne({email:email});
            if(!data) {
                return response.json({message: 'Data not found'});
            }
            const mailData = await sendResetToken.sendResetToken(email);
            const existingCode = await ResetCodes.findOne({userId:data._id});

            let date = new Date();
            date.setMinutes(date.getMinutes() + 5);

            if(!existingCode){
                const newResetCodes = new ResetCodes({
                    userId:data._id,
                    code: mailData,
                    duration: date,
                }); 
                await newResetCodes.save();
            }
            else{
                existingCode.code = mailData;
                existingCode.duration= date;
                await existingCode.save();
            }

            response.status(200).json({message: 'Email sent'});

        }catch(error){
            console.log(error);
            response.status(500).json({message: 'Internal server error'});
        }
    },

    resetPassword : async (request, response) => {
        const {code , email, newPassword} = request.body;
        try{
            const userData = await Users.findOne({email:email});
            if(!userData){
                return response.json({message:'Data not found'});
            }

            const resetCodes = await ResetCodes.findOne({userId:userData._id});
            const modifiedPassword = await bcrypt.hash(newPassword,10)

            if(resetCodes.code === code && resetCodes.duration > new Date()){
                userData.password = await bcrypt.hash(newPassword,10);
                await userData.save();
                console.log(userData.password);
                response.status(200).json({message:'Password reset successfull'});
            }
            else{
                return response.json({message:'otp expired Try again'});
            }
        } catch(error){
            console.log(error);
            response.status(500).json({message: 'Internal server error'});
        }
    }
};

module.exports = authController;