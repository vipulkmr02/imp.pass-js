import { loadEnvFile } from "process";
process.env.DEBUG && loadEnvFile(".env");
import express from "express";
import cors from "cors";
import { changePassword, registerUser, verifyUser } from "./middlewares";
import { ERROR, Errors } from "./errorMap";
import {
  createPassword,
  deletePassword,
  retrievePassword,
  updatePassword,
  updatePid,
} from "./data";

const app = express();
const PORT = parseInt(process.env.PORT ?? "9000");
app.use(express.json());
app.use(express.urlencoded());
app.use(cors({
  origin: ["http://:localhost:5173", process.env.FRONTEND_URL!],
  methods: ["GET", "PUT", "POST", "OPTIONS", "DELETE"],
  allowedHeaders: ["Content-Type", "Connection", "Cache-Control"],
  exposedHeaders: ["Content-Type", "Connection", "Cache-Control"],
  optionsSuccessStatus: 200,
}));

app.get("/", (_, res) => {
  res.send({ message: "The API is UP!" });
});

app.post("/register", (req, res) => {
  const { email, password } = req.body;
  registerUser(email, password).then(
    () => {
      res.send({
        message: "User Registered",
      });
    },
  ).catch((err: ERROR) => {
    res.status(500).send({ message: err.message });
  });
});

app.get("/new", verifyUser, (req, res) => {
  // retrieving all the ingredients of this operation
  const { pID, password } = req.body;
  const hash = req.headers.passwordHash;
  const email = req.headers.email;

  if (typeof hash == "string" && typeof email == "string") {
    createPassword({ pid: pID, password: password }, hash, email).then(() => {
      res.send({ message: "Created" });
    }).catch((err: Error) => {
      res.status(500).send({ message: err.message });
    });
  } else {
    // means that 'verifyUser' didn't set the passwordHash
    // probably because of user isn't found
    // verifyUser will already have sent the response
    // so no need to handle it here
    return;
  }
});

app.get("/password", verifyUser, (req, res) => {
  const pid = req.query.pID;
  const email = req.headers.email;
  const hash = req.headers.passwordHash;

  // retrieving Password
  if (typeof hash == "string") {
    if (typeof pid == "string" && typeof email == "string") {
      retrievePassword(pid, email, hash).then((pass) => {
        res.send({ password: pass, pid: pid });
      }).catch((err: ERROR) => {
        res.status(500).send({ message: err.message });
      });
    } else res.status(500).send({ message: "BAD REQUEST" });
  } else {
    // means that 'verifyUser' didn't set the passwordHash
    // probably because of user isn't found
    // verifyUser will already have sent the response
    // so no need to handle it here
    return;
  }
});

app.get("/delete", verifyUser, (req, res) => {
  const pid = req.query.pID;
  const user = req.headers.email;
  if (typeof req.headers.passwordHash == "string") {
    if (typeof pid == "string" && typeof user == "string") {
      deletePassword(pid, user).then((result) => {
        res.send({ message: `Password with pID ${pid} deleted` });
      });
    } else res.status(500).send({ message: "BAD REQUEST" });
  } else {
    // means that 'verifyUser' didn't set the passwordHash
    // probably because of user isn't found
    // verifyUser will already have sent the response
    // so no need to handle it here
    return;
  }
});

app.get("/update", verifyUser, (req, res) => {
  const pid = req.query.pID;
  const updated: { pID?: string; password?: string } = {};
  updated.pID = req.body.pID;
  updated.password = req.body.password;
  const user = req.headers.email;
  if (typeof req.headers.passwordHash == "string") {
    if (typeof user == "string" && typeof pid == "string") {
      if (updated.password) {
        updatePassword(
          pid,
          user,
          req.headers.passwordHash,
          updated.password,
        ).then(
          () => res.send({ message: "Updated" }),
        ).catch((err: ERROR) => {
          res.status(500).send({ message: err.message });
        });
      }
      if (updated.pID) {
        updatePid(pid, user, updated.pID).then(
          () => {
            res.send({ message: "pID updated!" });
          },
        ).catch((err) => res.status(500).send({ message: err.message }));
      }
    }
  } else {
    // means that 'verifyUser' didn't set the passwordHash
    // probably because of user isn't found
    // verifyUser will already have sent the response
    // so no need to handle it here
    return;
  }
});

app.get("/changePassword", verifyUser, (req, res) => {
  const { newPassword } = req.body;
  const hash: string = req.headers.passwordHash as string;
  const email: string = req.headers.email as string;

  if (typeof email === "string" && typeof newPassword === "string") {
    changePassword({ user: email, current: hash, newPassword: newPassword })
      .then(() => {
        res.send({ message: "Password Changed" });
      }).catch((err:Error) => {res.status(500).send(err.message)});
  } else res.status(500).send(Errors.WRONG_REQUEST);
});

app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});
