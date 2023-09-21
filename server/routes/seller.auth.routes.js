import express from "express";
import {signinSeller, createSeller, refresh, logout} from "../controllers/seller.auth.controller.js"

const router = express.Router();

router.route("/signin").post(signinSeller);
router.route("/refresh").get(refresh);
router.route("/logout").post(logout);
router.route("/signup").post(createSeller);

export default router;