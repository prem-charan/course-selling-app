const { Router } = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { z } = require("zod");

const { userModel } = require("../db");
const { JWT_USER_PASSWORD } = require("../config");

const userRouter = Router();

userRouter.post("/signup", async (req, res) => {
    const requiredBody = z.object({
        email: z.string().email(),
        password: z.string()
            .min(3, "Password must be at least 3 characters")
            .max(15, "Password must not exceed 15 characters")
            .regex(/[a-z]/, "Password must contain at least one lowercase letter")
            .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
            .regex(/\d/, "Password must contain at least one digit")
            .regex(/[^a-zA-Z0-9]/, "Password must contain at least one special character"),
        firstName: z.string().min(1).max(30),
        lastName: z.string().min(1).max(30)
    })
    const parsedData = requiredBody.safeParse(req.body);
    if (!parsedData.success) {
        return res.status(400).json({
            message: "Invalid input format",
            error: parsedData.error.issues.map(err => err.message)
        })
    }

    const { email, password, firstName, lastName } = parsedData.data;

    try {
        const existingEmail = await userModel.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ message: "User already exists"});
        }

        const hashedPassword = await bcrypt.hash(password, 10);
    
        await userModel.create({
            email: email,
            password: hashedPassword,
            firstName: firstName,
            lastName: lastName
        })

        return res.status(201).json({
            message: "User signup successful",
            user: {
                email,
                firstName,
                lastName
            }
        })
    } catch(e) {
        console.log(e);
        return res.json({
            message: "User signup failed" 
        })
    }
});

userRouter.post("/login", async (req, res) => {
    const loginSchema = z.object({
      email: z.string().email(),
      password: z.string().min(1, "Password is required")
    });

    const parsedData = loginSchema.safeParse(req.body);
    
    if (!parsedData.success) {
      return res.status(400).json({
        message: "Invalid input format",
        error: parsedData.error.issues.map((err) => err.message),
      });
    }

    const { email, password } = parsedData.data;

    try {
        const response = await userModel.findOne({ email });
        if (!response) {
            return res.status(404).json({ message: "User does not exist with that email" });
        }
    
        const passwordMatch = await bcrypt.compare(password, response.password);
        if (passwordMatch) {
            const token = jwt.sign({
                id: response._id.toString()
            }, JWT_USER_PASSWORD);
            
            return res.status(200).json({ 
                message: "User login successful",
                token
            });
        } else {
            return res.status(401).json({ message: "Incorrect user credentials" });
        }
    } catch(e) {
        console.log(e);
        return res.status(500).json({
            message: "Internal server error."
        })
    }
});

userRouter.get("/purchases", (req, res) => {
    res.json("user purchases endpoint")
})

module.exports = {
    userRouter: userRouter
}