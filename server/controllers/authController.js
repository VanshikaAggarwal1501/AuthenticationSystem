import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';


export const register= async(req,res) =>{
    const {name,email,password}= req.body;
    if(!name|| !email || !password) {
        return res.json({success:false, message:"Missing Details"});
    }
    try{
        const existingUser= await userModel.findOne({email});
        if(existingUser) {
            return res.json({success:false, message:"user already exists"});
        }
        const hashedPassword = await bcrypt.hash(password,10);
        const user= new userModel({name,email,password:hashedPassword});
        await user.save();
        // creating token 
        const token= jwt.sign({id:user._id}, process.env.JWT_SECRET, {expiresIn: '30d'});
        res.cookie('token', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'Lax',
            maxAge: 30 * 24 * 60 * 60* 1000
        });
        // sending email 
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome',
            text: `Welcome to My Website. Your Account has been successfully Created with the email is : ${email}`
        }
        await transporter.sendMail(mailOptions);
        return res.json({success:true});

    } catch(error){
        return res.json({success:false, message:error.message});
    }
}

export const login = async(req,res) =>{
    const {email,password}= req.body;
    if(!email || !password) {
        return res.json({success: false, message: "Email and password are required"});
    }
    try{
        const user= await userModel.findOne({email});
        if(!user) {
            return res.json({success:false, message:'Invalid Email'});
        }
        const isMatch= await bcrypt.compare(password, user.password);
        if(!isMatch){
            return res.json({success:false, message:'Invalid Password'});
        }
        const token= jwt.sign({id:user._id}, process.env.JWT_SECRET, {expiresIn: '30d'});
        res.cookie('token', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'Lax',
            maxAge: 30 * 24 * 60 * 60* 1000
        });
        return res.json({success:true,  message: "Logged In"});

    } catch(error) {
        return res.json({success:false, message:error.message});
    }
}
export const logout= async(req,res) =>{
    try{
        res.clearCookie('token', {
            httpOnly: true,
            secure: false,
            sameSite: 'Lax',
        });
        return res.json({success: true, message: "Logged Out"})

    } catch(error){
        return res.json({success:false, message:error.message});
    }
} 

export const sendVerifyOtp= async (req,res)=>{
    try{
        const {userId}= req.body;
        const user= await userModel.findById(userId);
        if(user.isAccountVerified){
            return res.json({success:false, message:"Account Already Verified"});

        }
        const otp= String(Math.floor(100000+ Math.random() * 900000));
        user.verifyOtp= otp;
        user.verifyOtpExpireAt= Date.now() + 24*60*60*1000;
        console.log("OTP to be saved:", otp);
        console.log("Before saving:", user.verifyOtp);
        await user.save();
        console.log("After saving:", user.verifyOtp);
        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            // text: `Your OTP for Verification is : ${otp}`,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }
        await transporter.sendMail(mailOption);
        return res.json({success:true, message: "OTP successfully sent for Verification"})

    } catch(error){
        return res.json({success:false, message:error.message});
    }
}
// verify account 
export const verifyEmail= async (req,res) => {
    const {userId, otp}= req.body;
    if(!userId || !otp) {
        return res.json({success:false, message: "Missing Details"});
    }
    try{
        const user = await userModel.findById(userId);
        user.verifyOtp= otp;
        // const updatedUser = await userModel.findById(userId);
        // console.log("Saved OTP in DB:", updatedUser.verifyOtp);
        if(!user) {
            return res.json({success:false, message: "User Not found"});

        }
        console.log("DB OTP:", user.verifyOtp);
        console.log("Received OTP:", String(otp));
        console.log("OTP to be saved:", otp);
        if(user.verifyOtp === '' || user.verifyOtp.trim() !== String(otp).trim()){
            return res.json({success:false, message: "Invalid OTP"})

        }
        if(user.verifyOtpExpireAt < Date.now()){
            return res.json({success:false, message: " OTP Expired"})
        }
        user.isAccountVerified= true;
        user.verifyOtp= '';
        user.verifyOtpExpireAt=0;
        await user.save();
        return res.json({success:true, message: " Email Verified Successfully"});
        


    } catch(error) {
        return res.json({success:false, message:error.message});

    }
}
export const isAuthenticated= async(req,res) => {
    try{

        return res.json({success:true, message: " User Authenticated"});

    } catch(error) {
        return res.json({success:false, message:error.message});
    }
}
//send passowrd reset otp 
export const sendResetOtp= async(req,res) => {
    const {email}= req.body;
    if(!email){
        return res.json({success:false, message:'Email is required'});
    }
    try{
        const user= await userModel.findOne({email});
        if(!user){
           return res.json({success:false, message:'User not found'});
        }
         const otp= String(Math.floor(100000+ Math.random() * 900000));
        user.resetOtp= otp;
        user.resetOtpExpireAt= Date.now() + 15*60*1000;
        console.log("OTP to be saved:", otp);
        console.log("Before saving:", user.resetOtp);
        await user.save();
        console.log("After saving:", user.resetOtp);
        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            // text: `Your OTP for resetting password is : ${otp}`
            html:PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }
        await transporter.sendMail(mailOption);
        return res.json({success:true, message: "OTP sent to your email"})

    } catch(error) {
        return res.json({success:false, message:error.message});

    }
}
// verify otp and reset user password
export const resetPassword= async(req,res) => {
    const {email, otp,newPassword}= req.body;
    if(!email || !otp || !newPassword) {
        return res.json({success:false, message: "Email, OTP and new passowrd are required"});
    }
    try{
        const user= await userModel.findOne({email});
        if(!user) {
           return res.json({success:false, message: "User Not found"}); 
        }
        if(user.resetOtp === "" || user.resetOtp!= otp){
            return res.json({success:false, message: "Invalid OTP"})
        }
        if(user.resetOtpExpireAt< Date.now() ){
            return res.json({success:false, message: "OTP Expired"})
        }
        const hashedPassword= await bcrypt.hash(newPassword,10);
        user.password= hashedPassword;
        user.resetOtp= "";
        user.resetOtpExpireAt=0;
        await user.save();
        return res.json({success:true, message: "Password has been reset Successfully"});


    } catch(error) {
        return res.json({success:false, message:error.message});
    }
}