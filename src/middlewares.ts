import { NextFunction, Request, Response } from "express";
import app from "./firebase";
import { ERRORS } from "./errorMap";
import {
  decodeToString,
  decrypt,
  getKey,
  encrypt,
  hashPassword,
  verifyHash,
  decryptwjkey,
  encryptwjkey,
} from "./crypt";
import { createSession, deleteSession, getSession, id } from "./data";

export const registerUser = async (
  email: string,
  password: string,
  confirmPassword: string,
) => {
  if (password !== confirmPassword)
    throw ERRORS.PASSWORDS_DO_NOT_MATCH

  const db = app.firestore();
  const uid = await id(email);
  const userDoc = db.doc(`users/${uid}`);

  // checking user's existence in the system.
  return userDoc.get().then((doc) => {
    if (doc.exists) throw ERRORS.USER_EXISTS;
    hashPassword(password, 10).then(
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
  if (req.body['_sessionID']) {
    next()
    return;
  }
  const db = app.firestore();
  const email = req.headers.email;
  const password = req.headers.password;

  // checking user before verifying
  if (email && password) {
    id(email as string).then((uid: string) =>
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
                    res.end();
                  } else {
                    // weird way of providing a single argument, right?
                    const key = (await getKey(password));

                    // create session
                    const { id: sessionID, data: sessionData } = await createSession(uid, key)
                    res.setHeader('Session', sessionID)  // this header is for frontend client.

                    req.body._sessionID = sessionID
                    req.body._sessionData = sessionData
                  }
                },
              );
            }
          }
        },
      )
    ).finally(next);
  } else res.status(400).send({ message: "Missing credential header" });
};

export const changePassword = async (opts: {
  userId: string;
  key: JsonWebKey;
  newPassword: string;
}) => {
  const { userId: user, key, newPassword } = opts;
  const db = app.firestore();
  const uid = await id(user);
  const passwordCol = db.collection(`data/${uid}/passwords`);
  const userDoc = db.doc(`users/${uid}`);

  // re-encrypting
  return userDoc.get().then(async (doc) => {
    if (!doc.exists) throw ERRORS.USER_NOT_FOUND;
    else {
      const newHash = await hashPassword(newPassword, 10);
      return await userDoc.update({ passwordHash: Buffer.from(newHash).toString('base64url') });
    }
  }).then(async () => {
    const newKey = await getKey(newPassword);
    passwordCol.get()
      .then(data =>
        data.forEach((doc) => {
          const enc: { cipher: string; iv: string } = doc.get("enc");
          decryptwjkey(enc, key).then(
            password => encryptwjkey(password, newKey),
          ).then(enc => doc.ref.update({ enc: enc }));
        })
      )
  })
};

export const session = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (req.body === undefined) req.body = {}
  // adding logs to this middleware
  const authHeader = req.headers.authorization
  if (authHeader?.match(/^Session/)) {
    const sessionID = authHeader.split(' ')[1]
    req.body._sessionID = sessionID;
    const sessionData = await getSession(sessionID)
    if (sessionData !== null) {
      const timeNow = new Date().valueOf();
      const sessionExpired = sessionData.expireOn < timeNow;
      if (sessionExpired) {
        await deleteSession(sessionID)
        res.status(ERRORS.SESSION_EXPIRED.code).send({ message: ERRORS.SESSION_EXPIRED.message })
        return;
      }
      req.body._sessionData = sessionData
    }
  } next()
}
