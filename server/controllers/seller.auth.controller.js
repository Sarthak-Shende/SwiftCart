import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Seller from "../models/seller.js"

const signinSeller = async (req,res) => {
    try{
        const {email,password} = req.body;

        if(!email || !password){
            return res.status(400).json({message:"All fields required"});
        }
        
        const seller = await Seller.findOne({email});

        if(!seller){
            res.status(400).send("Seller not registered");
            return;
        }

        const isMatch = await bcrypt.compare(password, seller.password);

        if(!isMatch){
            res.status(400).send("Enter correct password");
        }

        const accessToken = jwt.sign(
            {
                "SellerInfo":{
                    "email":seller.email,
                }
            },
            process.env.ACCESS_TOKEN_SECRET_SELLER,
            {expiresIn:"15m"}
        )

        const refreshToken = jwt.sign(
            {
                "email":seller.email
            },
            process.env.REFRESH_TOKEN_SECRET_SELLER,
            {expiresIn:"3d"}
        )

        res.cookie("jwt", refreshToken, {
            httpOnly:true,
            sameSite:"None",
            maxAge: 3 * 24 * 60 * 60 * 1000
        })

        res.json({accessToken});

    }catch(error){
        res.status(500).json({message:error.message});
    }
}

const refresh = async(req,res) => {
    try {
        const cookies = req.cookies;

        if(!cookies?.jwt){
            return res.stauts(401).json({message:"Unauthorized"});
        }

        const refreshToken= cookies.jwt;

        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET_SELLER,
            async(err,decoded) => {
                if(err){
                    return res.status(403).json({message:"Forbidden"});
                }

                const foundSeller = Seller.findOne({email:decoded.email});

                if(!foundSeller){
                    return res.status(401).json({message:"Unauthorized"});
                }

                const accessToken = jwt.sign(
                    {
                        "SellerInfo":{
                            email:foundSeller.email
                        }
                    },
                    process.env.ACCESS_TOKEN_SECRET_SELLER,
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
    if(!cookies){
        return res.sendStatus(204);
    }

    res.clearCookie("jwt", { httpOnly:true, sameSite:"None"} )

    res.json({message:"Cookie cleared"});
}

const createSeller = async (req,res) => {
    try {
        const {email, password} =req.body;

        if(!email || !password){
            return res.status(400).json({message:"All fields required"});
        }

        const emailExist = await Seller.findOne({email:email});

        if(emailExist){
            return res.status(400).send("Email already exists");
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newSeller = await Seller.create({
            email:email,
            password:hashedPassword
        });

        res.status(200).json(newSeller);
    } catch (error) {
        res.status(500).json({message:error.message});
    }
}

export { signinSeller, refresh, logout, createSeller};