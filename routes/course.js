const { Router } = require("express");
const { userMiddleware } = require("../middleware/user");
const { purchaseModel, courseModel } = require("../db");

const courseRouter = Router();

courseRouter.get("/preview", async (req, res) => {
    const courses = await courseModel.find({});

    res.json({
        message: "all courses preview endpoint",
        courses
    })
})

courseRouter.post("/purchase", userMiddleware, async (req, res) => {
    const userId = req.userId;
    const courseId = req.body.courseId;

    await purchaseModel.create({
        userId,
        courseId
    })

    res.json("You have successfully bought the course")
})

module.exports = {
    courseRouter: courseRouter
}