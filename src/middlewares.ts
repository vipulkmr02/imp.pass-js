import { NextFunction, Request, Response } from "express";
import app from "./firebase";
import { ERRORS } from "./errorMap";
import {
  decodeToString,
  decryptwjkey,
  encryptwjkey,
  getKey,
  hashPassword,
  verifyHash,
} from "./crypt";
import { createSession, deleteSession, getSession, id } from "./data";

export const registerUser = async (
  email: string,
  password: string,
) => {
  const db = app.firestore();
  const uid = await id(email);
  const userDoc = db.doc(`users/${uid}`);

  // checking user's existence in the system.
  return userDoc.get().then((doc) => {
    if (doc.exists) throw ERRORS.USER_EXISTS;
    return hashPassword(password, 10).then(
      (hashedPass) =>
        userDoc.set({
          email: email,
          passwordHash: Buffer.from(hashedPass).toString("base64url"),
        }).catch(() => {
          throw ERRORS.CANT_CREATE_USER;
        }),
    );
  });
};

export const verifyUser = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  console.log("[VERIFYING USER]");
  if (req.body["_sessionID"]) {
    console.log("Session ID found");
    next();
    return;
  }
  const db = app.firestore();
  const email = req.headers.email;
  const password = req.headers.password;

  // checking user before verifying
  if (email && password) {
    console.log("email", email);
    console.log("password", password);
    return id(email as string).then((uid: string) =>
      db.doc(`users/${uid}`).get().then(
        async (doc) => {
          if (!doc.exists) {
            const err = ERRORS.USER_NOT_FOUND;
            res.status(err.code).send({
              message: err.message,
            });
            res.end();
          } else {
            const passwordHash = doc.get("passwordHash");
            if (typeof password === "string") {
              await verifyHash(password, decodeToString(passwordHash)).then(
                async (equal) => {
                  if (!equal) {
                    const err = ERRORS.WRONG_PASSWORD;
                    res.status(err.code).send({
                      message: err.message,
                    });
                    console.error(err.message);
                    res.end();
                  } else {
                    // weird way of providing a single argument, right?
                    const key = await getKey(password);

                    // create session
                    const session  = await createSession(uid, key);
                    debugger;
                    res.setHeader("Session", session.id); // this header is for frontend client
                    req.body._sessionID = session.id;
                    req.body._sessionData = session.data;
                  }
                },
              );
            }
          }
        },
      )
    ).finally(next);
  } else res.status(40).send({ message: "Missing credential header" });
};

export const changePassword = async (opts: {
  userId: string;
  key: JsonWebKey;
  newPassword: string;
  sessionID?: string;
}) => {
  const { userId: user, key, newPassword, sessionID } = opts;
  const db = app.firestore();
  const newKey = await getKey(newPassword);
  const passwordCol = db.collection(`data/${user}/passwords`);
  const userDoc = db.doc(`users/${user}`);
  const sessionDoc = db.doc(`sessions/${sessionID}`);
  const userDocData = await userDoc.get();
  if (!userDocData.exists) throw ERRORS.USER_NOT_FOUND;
  else {
    const newHash = await hashPassword(newPassword, 10);
    userDoc.update({ passwordHash: newHash });
    const passwordCollection = await passwordCol.get();
    let recordsUpdated = 0; for (const doc of passwordCollection.docs) { const enc: { cipher: string; iv: string } = doc.get("enc");
      const password = await decryptwjkey(enc, key);
      const newEnc = await encryptwjkey(password, newKey);
      recordsUpdated++;
      await doc.ref.update({ enc: newEnc });
    }
    if (sessionID) await sessionDoc.update({ key: newKey });
    return recordsUpdated;
  }
};

export const session = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  // this is session middleware
  const authHeader = req.headers.authorization;
  if (authHeader?.match(/^Session/)) {
    const sessionID = authHeader.split(" ")[1];
    req.body._sessionID = sessionID;
    const sessionData = await getSession(sessionID);
    if (sessionData !== null) {
      // if sessionData is found
      // first we will check if 
      // it's expired or not
      const timeNow = new Date().valueOf();
      const sessionExpired = sessionData.expireOn < timeNow;
      if (sessionExpired) {
        // if expired, we will delete
        // the session on our database.
        await deleteSession(sessionID);
        res.status(ERRORS.SESSION_EXPIRED.code).send(
          { message: ERRORS.SESSION_EXPIRED.message },
        );
        return;
      }
      req.body._sessionData = sessionData;
    }
    // if sessionData is not found in the Database,
    // then the body._sessionData will be undefined
  }
  next();
};

// export const identify = async (sessionID: string) => {
//   const sessionData = await getSession(sessionID);
//   if (sessionData !== null) {
//     const userId = sessionData.userId
//
//     // High Level overview:
//     // From this userId, we'll retrieve the doc from our DB
//     // and that doc will be having the user's details
//
//     const db = app.firestore()
//     const docRef = db.collection('users').doc(userId)
//     const doc = await docRef.get()
//     const docData = doc.data()
//
//     return docData;
//   } 
// }

export const body = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  if (!req.body) {
    req.body = {};
  }
  next();
};
