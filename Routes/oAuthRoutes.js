import express from "express";
import { googleLogin, googleRegister } from "../Controllers/oAuthController.js";

const oAuthRoute = express.Router();

oAuthRoute.post("/google-register", googleRegister);
oAuthRoute.post("/google-login", googleLogin);

export default oAuthRoute;
