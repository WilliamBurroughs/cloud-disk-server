const express = require("express");
const mongoose = require("mongoose");
const config = require("config");
const fileUpload = require("express-fileupload");
const authRouter = require("./routes/auth.routes");
const fileRouter = require("./routes/file.routes");
const PORT = process.env.PORT || config.get("serverPort");
const corsMiddleware = require("./middleware/cors.middleware");
const filePathMiddleware = require("./middleware/filepath.middleware");
const path = require("path");
const app = express();

app.use(fileUpload({}));
app.use(corsMiddleware);
app.use(filePathMiddleware(path.resolve(__dirname, "files")));
app.use(express.json());
app.use("/api/auth", authRouter);
app.use("/api/files", fileRouter);

const start = async () => {
  try {
    mongoose.set("strictQuery", false);
    mongoose.connect(config.get("dbUrl"));

    app.listen(PORT, () => {
      console.log("Server started on port ", PORT);
    });
  } catch (error) {
    console.log("Error! Server connection interrupted: ", error);
  }
};

start();
