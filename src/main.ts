import { loadEnvFile } from "process";
process.env.DEBUG && loadEnvFile(".env");
import express from "express";
import cors from "cors";
import {
  body,
  changePassword,
  registerUser,
  session,
  verifyUser,
} from "./middlewares";
import { ERROR, ERRORS } from "./errorMap";
import {
  createPassword,
  deletePassword,
  retrieveAllPasswords,
  retrievePassword,
  updatePassword,
  updatePid,
  deleteExpiredSessions
} from "./data";

const app = express();
const PORT = process.env.PORT ?? 9000;
app.use(express.json());
app.use(express.urlencoded());

// BUG: Fix CORS configuration
// app.use(cors());
app.use(cors({
  origin: ["http://localhost:9000", process.env.FRONTEND_URL!],
  methods: ["GET", "PUT", "POST", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Connection",
    "Cache-Control",
    "Authorization",
    "email",
    "password",
    "Access-Allow-Origin"
  ],
  exposedHeaders: ["Content-Type", "Connection", "Cache-Control", "Session"],
  optionsSuccessStatus: 200,
  credentials: true,
}));
app.use(body);
app.use(session); // custom session middleware

app.get("/", (_, res) => {
  res.send({ message: "The API is UP!" });
});

app.post("/register", (req, res) => {
  const { email, password } = req.body;
  registerUser(email, password).then(
    () => res.send({ message: "User Registered" }),
  ).catch((err: ERROR) => {
    if (err.code) {
      res.status(err.code).send({ message: err.message });
    } else {
      res.status(500).send({ message: "Something went wrong." });
      console.error("ERROR:", err);
    }
  });
});

app.get("/identify", verifyUser, (req, res) => {
})

app.get("/initSession", verifyUser, (req, res) => {
  if (req.body._sessionID) {
    res.send({ sessionID: req.body._sessionID });
  }
});

app.get("/validateSession", session, (req, res) => {
  if (req.body._sessionData) res.send({ sessionOk: true });
  else res.send(res.send({ sessionOk: false }));
});

app.put("/new", verifyUser, (req, res) => {
  // retrieving all the ingredients of this operation
  const { pID, password, _sessionData } = req.body;
  const { key, userId } = _sessionData;

  if (key && userId) {
    createPassword({ pid: pID, password: password }, key, userId).then(() => {
      res.send({ message: "Created" });
    }).catch((err: ERROR) => {
      if (err.code) {
        res.status(err.code).send({ message: err.message });
      } else {
        console.error(err);
        res.status(500).send({ message: "Something went wrong." });
      }
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
  const id = req.query.id;
  // const email = req.headers.email;
  // const hash = req.headers.passwordHash;
  const { key, userId } = req.body._sessionData;

  if (key && userId) {
    if (typeof pid == "string" && typeof userId == "string") {
      if (pid == "all") {
        retrieveAllPasswords(userId, key).then((docs) => {
          res.send(docs);
        });
      } else {
        retrievePassword(pid, userId, key).then((pass) => {
          res.send({ password: pass, pid: pid });
        }).catch((err: ERROR) => {
          console.log(err.message);
          res.status(err.code ?? 500).send({
            message: err.code ? err.message : "Something went wrong",
          });
        });
      }
    } else res.status(500).send({ message: "BAD REQUEST" });
  } else {
    // means that 'verifyUser' didn't set the passwordHash probably because of
    // user isn't found verifyUser will already have sent the response so no
    // need to handle it here
    return;
  }
});

app.get("/delete", verifyUser, (req, res) => {
  const pid = req.query.pID as string;
  const { userId } = req.body._sessionData;

  if (pid) {
    deletePassword(pid, userId).then(() => {
      res.send({ message: `Password with pID ${pid} deleted` });
    });
  } else res.status(500).send({ message: "pid empty" });
});

// route: /update
// updates the existing passwords
app.put("/update", verifyUser, (req, res) => {
  const pid = req.query.pID as string;
  const updated: { pID?: string; password?: string } = {};
  updated.pID = req.body.pID;
  updated.password = req.body.password;
  const { key, userId } = req.body._sessionData;
  if (key && userId && pid) {
    if (updated.password) {
      updatePassword(
        pid,
        userId,
        key,
        updated.password,
      ).then(
        () => res.send({ message: "Updated" }),
      ).catch((err: ERROR) => {
        res.status(err.code ?? 500).send(
          { message: err.code ? err.message : "Something went wrong." },
        );
      });
    }
    if (updated.pID) {
      updatePid(pid, userId, updated.pID).then(
        () => res.send({ message: "pID updated!" }),
      ).catch((_err) =>
        res.status(_err.code ?? 500).send(
          { message: _err.code ? _err.message : "Something went wrong." },
        )
      );
    }
  } else {
    // means that 'verifyUser' didn't set the passwordHash
    // probably because of user isn't found
    // verifyUser will already have sent the response
    // so no need to handle it here
    return;
  }
});

// route: changePassword
// Changes the user main password and re-encrypt existing passwords with the
// new keys.
app.put("/changePassword", verifyUser, (req, res) => {
  const { newPassword, _sessionData, _sessionID: sessionID } = req.body;
  const { key, userId } = _sessionData;

  if (typeof userId === "string" && typeof newPassword === "string") {
    changePassword({
      userId: userId,
      key: key,
      newPassword: newPassword,
      sessionID: sessionID,
    })
      .then((recordsUpdated) => {
        res.send({
          message: "Password Changed",
          recordsUpdated: recordsUpdated,
        });
      }).catch((err: ERROR) => {
        res.status(err.code ?? 500).send({
          message: err.code ? err.message : "Something went wrong",
        });
      });
  } else res.status(500).send(ERRORS.WRONG_REQUEST);
});


// this here is a time based trigger
// that deletes expired sessions from the database
// this function will run every 5 second
// and look for expired sessions and will delete them.


app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
  setInterval(deleteExpiredSessions, 5000)
});
