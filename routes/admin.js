const { Router } = require("express");
const { adminModel, courseModel } = require("../db");
const bcrypt = require("bcrypt");
const { z } = require("zod"); 
const jwt = require("jsonwebtoken");

const adminRouter = Router();
const { JWT_ADMIN_PASSWORD } = require("../config");
const { adminMiddleware } = require("../middleware/admin");

adminRouter.post("/signup", async (req, res) => {
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
    if (! parsedData.success) {
        return res.status(400).json({
            message: "Invalid input format",
            error: parsedData.error.issues.map(err => err.message)
        })
    }

    const { email, password, firstName, lastName } = parsedData.data;

    try {
        const existingEmail = await adminModel.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ message: "Admin already exists"});
        }

        const hashedPassword = await bcrypt.hash(password, 10);
    
        await adminModel.create({
            email: email,
            password: hashedPassword,
            firstName: firstName,
            lastName: lastName
        })

        return res.status(201).json({
            message: "Admin signup successful",
            admin: {
                email,
                firstName,
                lastName
            }
        })
    } catch(e) {
        console.log(e);
        return res.json({
            message: "admin signup failed" 
        })
    }
});

adminRouter.post("/login", async (req, res) => {
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
        const response = await adminModel.findOne({ email });
        if (!response) {
            return res.status(404).json({ message: "Admin does not exist with that email" });
        }
    
        const passwordMatch = await bcrypt.compare(password, response.password);
        if (passwordMatch) {
            const token = jwt.sign({
                id: response._id.toString()
            }, JWT_ADMIN_PASSWORD);
            
            return res.status(200).json({ 
                message: "Admin login successful",
                token
            });
        } else {
            return res.status(401).json({ message: "Incorrect admin credentials" });
        }
    } catch(e) {
        console.log(e);
        return res.status(500).json({
            message: "Internal server error."
        })
    }
});

adminRouter.post("/course",adminMiddleware, async (req, res) => {
    const adminId = req.adminId;

    const { title, description, imageUrl, price } = req.body;

    const course = await courseModel.create({
        title: title,
        description: description,
        imageUrl: imageUrl,
        price: price,
        creatorId: adminId
    })

    res.json({
        message: "Course created",
        courseId: course._id
    })
})

adminRouter.put("/course",adminMiddleware, async (req, res) => {
    const adminId = req.adminId;

    const { title, description, imageUrl, price, courseId } = req.body;

    const course = await courseModel.updateOne({
        _id: courseId,
        creatorId: adminId
    }, {
        title: title,
        description: description,
        imageUrl: imageUrl,
        price: price
    })

    res.json({
        message: "Course updated",
        courseId: course._id
    })
});

adminRouter.get("/course/bulk", adminMiddleware, async (req, res) => {
    const adminId = req.adminId;

    const courses = await courseModel.find({
        creatorId: adminId,
    })

    res.json({
        message: "All courses fetched",
        courses
    })
});

module.exports = {
    adminRouter: adminRouter
}