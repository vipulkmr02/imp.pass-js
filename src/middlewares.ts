import { NextFunction, Request, Response } from "express";
import app from "./firebase";
import { Errors } from "./errorMap";
import {
  decodeToString,
  decrypt,
  encrypt,
  hashPassword,
  verifyHash,
} from "./crypt";
import { id } from "./data";

export const registerUser = async (
  email: string,
  password: string,
) => {
  const db = app.firestore();
  const uid = await id(email);
  const userDoc = db.doc(`users/${uid}`);

  // checking user's existence in the system.
  return userDoc.get().then((doc) => {
    if (doc.exists) throw Errors.USER_EXISTS;
    hashPassword(password, 10).then(
      (hashedPass) =>
        userDoc.set({
          email: email,
          passwordHash: Buffer.from(hashedPass).toString("base64url"),
        }).catch(() => {
          throw Errors.USER_NOT_CREATING;
        }),
    );
  });
};

export const verifyUser = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const db = app.firestore();
  const email = req.headers.email;
  const password = req.headers.password;

  // checking user before verifying
  if (email && password) {
    id(email as string).then((uid:string) =>
      db.doc(`users/${uid}`).get().then(
        async (doc) => {
          if (!doc.exists) {
            const err = Errors.USER_NOT_FOUND;
            res.status(err.code).send({
              message: err.message,
            });
            res.end();
          } else {
            const passwordHash = doc.get("passwordHash");
            if (typeof password === "string") {
              await verifyHash(password, decodeToString(passwordHash)).then(
                (equal) => {
                  if (!equal) {
                    const err = Errors.WRONG_PASSWORD;
                    res.status(err.code).send({
                      message: err.message,
                    });
                    res.end();
                  } else {
                    req.headers.passwordHash = passwordHash;
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
  user: string;
  current: string;
  newPassword: string;
}) => {
  const { user, current, newPassword } = opts;
  const db = app.firestore();
  const uid = await id(user);
  const passwordCol = db.collection(`data/${uid}/passwords`);
  const userDoc = db.doc(`users/${uid}`);

  // re-encrypting
  return userDoc.get().then(async (doc) => {
    if (!doc.exists) throw Errors.USER_NOT_FOUND;
    else {
      const newHash = await hashPassword(newPassword, 10);
        return await userDoc.update({ passwordHash: Buffer.from(newHash).toString('base64url') });
    }
  }).then(() =>
    passwordCol.get()
      .then((data) =>
        data.forEach((doc) => {
          const enc: { cipher: string; iv: string } = doc.get("enc");
          decrypt(enc, current).then(
            (password) => encrypt(password, newPassword),
          ).then((enc) => {
            doc.ref.update({ enc: enc });
          });
        })
      )
  );
};

// notes:
// creds: ghk@gmail.com (ghk)
// previous Hash: JDJiJDEwJGs4QlBLSWtEa0ZFazVGMnVMNHdXZi5zaXhhMXpZUUVaV2IuUGZZRm5rWFN3US5ubjJnWnc2
// previous Passwords:
// pID: google
// cipher : WAcVy5esmu4xJ7tG31dNH-OWqy4_jg
// iv: gfKRhXrLd4gAp8iw
// Changing Password => GHK
// new Hash: 
