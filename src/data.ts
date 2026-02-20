import {
  decrypt,
  decryptwjkey,
  encodeToString,
  encrypt,
  encryptwjkey,
} from "./crypt";
import { ERRORS } from "./errorMap";
import app from "./firebase";

export async function id(pid: string) {
  const hash = await crypto.subtle.digest(
    "SHA-1",
    Buffer.from(pid),
  );
  return encodeToString(hash);
}

export async function createPassword(
  password: { pid: string; password: string },
  key: JsonWebKey,
  userId: string,
) {
  const db = app.firestore();
  const dataCollection = db.collection("data");
  const docId = await id(password.pid);
  const docRef = dataCollection.doc(userId)
    .collection("passwords").doc(docId);

  return docRef.get().then((result) => {
    if (result.exists) throw ERRORS.PID_EXISTS;
  }).then(() =>
    encryptwjkey(password.password, key)
      .then((enc) => docRef.set({ pID: password.pid, enc: enc }))
  );
}

export async function retrievePasswordById(
  id: string,
  userId: string,
  key: JsonWebKey,
) {
  const db = app.firestore();
  const dataColl = db.collection("data");
  const docRef = dataColl.doc(`${userId}/passwords/${id}`);
  return docRef.get().then(
    async (docSnap) => {
      return {
        pID: docSnap.get('pID'),
        password: await decryptwjkey(docSnap.get("enc"), key),
        _id: docSnap.id,
      };
    },
  );
}

export async function retrievePassword(
  pid: string,
  userId: string,
  key: JsonWebKey,
) {
  const db = app.firestore();
  const dataCollection = db.collection("data");
  const docId = await id(pid);

  return dataCollection.doc(userId)
    .collection("passwords").doc(docId).get().then(
      async (doc) => {
        if (doc.exists) {
          try {
            return await decryptwjkey(doc.get("enc"), key);
          } catch {
            throw "Error while decrypting.";
          }
        } else throw ERRORS.PID_NOT_EXISTS;
      },
    );
}

export async function retrieveAllPasswords(userId: string, key: JsonWebKey) {
  const db = app.firestore();
  const passwordsCollectionRef = db.collection(`data/${userId}/passwords`);
  const collection = await passwordsCollectionRef.get();
  const passwordPromises = collection.docs.map(async (doc) => {
    return {
      _id: doc.id,
      pID: doc.get("pID"),
      password: await decryptwjkey(await doc.get("enc"), key),
    };
  });
  return await Promise.all(passwordPromises);
}

export async function deletePassword(pid: string, userId: string) {
  const db = app.firestore();
  const dataCollection = db.collection("data");
  const docId = await id(pid);
  const docRef = dataCollection.doc(userId)
    .collection("passwords").doc(docId);
  return docRef.delete();
}

export async function updatePassword(
  pid: string,
  userId: string,
  key: JsonWebKey,
  updatedPassword: string,
) {
  const db = app.firestore();
  const dataCollection = db.collection("data");
  const docId = await id(pid);
  const docRef = dataCollection.doc(userId)
    .collection("passwords").doc(docId);
  return docRef.get().then(async (res) => {
    if (res.exists) {
      const enc = await encryptwjkey(updatedPassword, key);
      docRef.update({ enc: enc });
    } else {
      throw ERRORS.PID_NOT_EXISTS;
    }
  });
}

export async function updatePid(
  pid: string,
  userId: string,
  updatedPid: string,
) {
  const db = app.firestore();
  const dataCollection = db.collection("data");
  const docId = await id(pid);
  const newDocId = await id(updatedPid);
  const oldDoc = dataCollection.doc(userId).collection("passwords").doc(docId);
  const newDoc = dataCollection.doc(userId).collection("passwords").doc(
    newDocId,
  );

  return oldDoc.get().then((data) => {
    const oldData = data.data();
    if (oldData) {
      oldData["pID"] = updatedPid;
      return newDoc.set(oldData);
    }
  }).then(() => oldDoc.delete());
}

export async function createSession(userId: string, key: JsonWebKey) {
  console.log("Creating Session...");
  const db = app.firestore();
  const sessionIdBin = crypto.getRandomValues(new Uint8Array(32)); // key
  const sessionIdStr = encodeToString(sessionIdBin.buffer); // encoding key to string
  const docRef = db.collection("sessions").doc(sessionIdStr);
  const creationDateEpoch = new Date().valueOf();
  const data: sessionData = {
    userId: userId,
    key: key,
    createdOn: creationDateEpoch,
    lastUsedOn: creationDateEpoch,
    expireOn: creationDateEpoch + 120_000, // 2 minutes
  };
  await docRef.set(data);
  console.log("Session Created");
  return { id: sessionIdStr, data: data };
}

interface sessionData {
  userId: string;
  key: JsonWebKey;
  createdOn: number;
  lastUsedOn: number;
  expireOn: number;
}

/**
 * Retrieves the document from database
 * and converts to native JS object
 */
export async function getSession(
  sessionId: string,
): Promise<null | sessionData> {
  const db = app.firestore();
  const docRef = db.collection("sessions").doc(sessionId);
  const docSnapshot = await docRef.get();
  if (!docSnapshot.exists) return null;
  else return docSnapshot.data() as sessionData;
}

export async function deleteSession(sessionId: string) {
  const db = app.firestore();
  const docRef = db.collection("sessions").doc(sessionId);
  return docRef.delete();
}

export async function deleteExpiredSessions() {
  const db = app.firestore();
  const docs = await db.collection("sessions").get()
  docs.forEach(async (docData) => {
    const nowSeconds = (new Date()).valueOf()
    if (nowSeconds > docData.data().expireOn) {
      console.log("deleting session", docData.id);
      await docData.ref.delete()
    }
  })
}
