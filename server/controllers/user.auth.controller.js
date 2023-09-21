import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/user.js";
 
const signinUser = async (req,res) => {
    try{
        const {email,password} = req.body;

        if(!email || !password){
            return res.status(400).json({message:"All fields required"});
        }
        
        const user = await User.findOne({email});

        if(!user){
            res.status(400).send("User not registered");
            return;
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch){
            res.status(400).send("Enter correct password");
        }

        const accessToken = jwt.sign(
            {
                "UserInfo":{
                    "email":user.email,
                }
            },
            process.env.ACCESS_TOKEN_SECRET_USER,
            {expiresIn:"15m"}
        )

        const refreshToken = jwt.sign(
            {
                "email":user.email
            },
            process.env.REFRESH_TOKEN_SECRET_USER,
            {expiresIn:"3d"}
        )

        res.cookie("jwt", refreshToken, {
            httpOnly:true,
            secure:true,
            sameSite:"None",
            maxAge: 3 * 24 * 60 * 60 * 1000
        })

        res.json({accessToken});

    }catch(error){
        res.status(500).json({message:error.message});
    }
}

const refresh = (req,res) => {
    try {
        const cookies = req.cookies;
        //console.log(req);
        if(!cookies?.jwt){
            return res.status(401).json({message:"Cookies not sent"});
        }

        const refreshToken= cookies.jwt;

        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET_USER,
            async(err,decoded) => {
                if(err){
                    return res.status(403).json({message:"Forbidden"});
                }

                const foundUser = await User.findOne({email:decoded.email});

                if(!foundUser){
                    return res.status(401).json({message:"Unauthorized"});
                }

                const accessToken = jwt.sign(
                    {
                        "UserInfo":{
                            email:foundUser.email
                        }
                    },
                    process.env.ACCESS_TOKEN_SECRET_USER,
                    {expiresIn:"15m"}
                )

                res.json(accessToken);
            }
        )
    } catch (error) {
        res.status(500).json({message:error.message});
    }
}

const logout = async (req,res) => {
    const cookies = req.cookies;
    if(!cookies?.jwt){
        return res.sendStatus(204);
    }

    res.clearCookie("jwt", { httpOnly:true, sameSite:"None", secure:true} )

    res.json({message:"Cookie cleared"});
}

const createUser = async (req,res) => {
    try {
        const {email, password} =req.body;

        if(!email || !password){
            return res.status(400).json({message:"All fields required"});
        }

        const emailExist = await User.findOne({email:email});

        if(emailExist){
            return res.status(400).send("Email already exists");
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({
            email:email,
            password:hashedPassword
        });

        res.status(200).json(newUser);
    } catch (error) {
        res.status(500).json({message:error.message});
    }
}

export { signinUser, refresh, logout, createUser};