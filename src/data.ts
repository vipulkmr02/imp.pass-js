import { decrypt, encodeToString, encrypt } from "./crypt";
import { Errors } from "./errorMap";
import app from "./firebase";


function id(pid: string) {
  return crypto.subtle.digest(
    'SHA-1', Buffer.from(pid)).then(hash =>
      encodeToString(hash)
    )
}

export async function createPassword(password: { pid: string, password: string }, hash: string, user: string) {
  const db = app.firestore()
  const dataCollection = db.collection('data')
  const userId = await id(user)
  const docId = await id(password.pid)
  const docRef = dataCollection.doc(userId)
    .collection('passwords').doc(docId)

  return docRef.get().then((result) => {
    if (result.exists)
      throw Errors.PID_EXISTS
  }).then(() => encrypt(password.password, hash)
    .then(enc => docRef.set({ pID: password.pid, enc: enc }))
  )
}

export async function retrievePassword(pid: string, user: string, hash: string) {
  const db = app.firestore()
  const dataCollection = db.collection('data')
  const userId = await id(user)
  const docId = await id(pid)

  return id(pid).then(() => dataCollection.doc(userId)
    .collection('passwords').doc(docId).get().then(
      (doc) => {
        if (doc.exists) return decrypt(doc.get('enc'), hash).catch(() => { throw "Error while decrypting." })
        else throw Errors.PID_NOT_EXISTS;
      }
    )
  )
}

export async function deletePassword(pid: string, user: string) {
  const db = app.firestore()
  const dataCollection = db.collection('data')
  const userId = await id(user)
  const docId = await id(pid)
  const docRef = dataCollection.doc(userId)
    .collection('passwords').doc(docId)
  return docRef.delete()
}

export async function updatePassword(
  pid: string,
  user: string,
  masterPassword: string,
  updatedPassword: string
) {
  const db = app.firestore()
  const dataCollection = db.collection('data')
  const userId = await id(user)
  const docId = await id(pid)
  const docRef = dataCollection.doc(userId)
    .collection('passwords').doc(docId)
  return docRef.get().then((res) => {
    if (res.exists) {
      return encrypt(updatedPassword, masterPassword)
        .then(enc => {
          docRef.update({ enc: enc })
        })
    } else {
      throw Errors.PID_NOT_EXISTS
    }
  })
}

export async function updatePid(
  pid: string, user: string, updatedPid: string
) {
  const db = app.firestore()
  const dataCollection = db.collection('data')
  const userId = await id(user)
  const docId = await id(pid)
  const newDocId = await id(pid)
  const oldDoc = dataCollection.doc(userId).collection('passwords').doc(docId);
  const docRef = dataCollection.doc(userId).collection('passwords').doc(newDocId)

  return oldDoc.get().then(() => docRef.get().then((res) => {
    if (res.exists) {
      return docRef.update({ pID: updatedPid })
    } else {
      throw Errors.PID_NOT_EXISTS
    }
  }))
}

