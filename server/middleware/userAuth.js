import jwt from 'jsonwebtoken'

const userAuth = async(req,res,next) =>{
    console.log(req.cookies);
    const {token}= req.cookies;
    if(!token) {
        return res.json({success:false, message:"Not Authorized. Login Again"})
    }
    console.log("token received successfully");

    try{
        const tokenDecode= jwt.verify(token, process.env.JWT_SECRET);
        if(tokenDecode.id){
            req.body = req.body || {};
            req.body.userId= tokenDecode.id;
        } else {
            return res.json({success:false, message:"Not Authorized, Login Again"});
        }
        next();

    } catch(error){
        return res.json({success:false, message: error.message})
    }
}
export default userAuth