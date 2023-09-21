import express from "express";
import {signinUser, createUser, refresh, logout } from "../controllers/user.auth.controller.js"

const router = express.Router();

router.route("/signin").post(signinUser);
router.route("/refresh").get(refresh);
router.route("/logout").post(logout);
router.route("/signup").post(createUser);

export default router;