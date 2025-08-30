const { Router } = require("express");

const courseRouter = Router();

courseRouter.get("/preview", (req, res) => {
    res.json("all courses preview endpoint")
})

courseRouter.post("/purchase", (req, res) => {
    res.json("purchase a course endpoint")
})

module.exports = {
    courseRouter: courseRouter
}