const { text } = require('body-parser');
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service:"gmail",
    auth:{
        user:process.env.GMAIL_EMAIL_ID,
        pass:process.env.GMAIL_APP_PASSWORD
    }
});

const generateResetToken = () => {
    const char = "abcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";

    for(let i = 0;i<6;i++){
        result += char[Math.floor(Math.random()*char.length)];
    }
    return result;
}

const sendResetToken = async (to) => {
    const otp = generateResetToken();
    try{
        const emailOptions = {
            to:to,
            from: process.env.GMAIL_EMAIL_ID,
            text:`Your one-time-password is ${otp}`,
            subject:"Your OTP for reseting your password"
        }
        const data = await transporter.sendMail(emailOptions);
        if(data){
            console.log(data);
        }
        else{
            console.log("email not sent");
        }
        return otp;
    }catch(error){
        console.log(error);
    }
}

module.exports = {sendResetToken};