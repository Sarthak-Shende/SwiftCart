import mongoose from "mongoose";

const SellerSchema = new mongoose.Schema({
    email:{type: String, required:true},
    password:{type: String, required:true}
});

const sellerModel= mongoose.model("Seller", SellerSchema);

export default sellerModel;