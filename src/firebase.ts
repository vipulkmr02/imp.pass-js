import admin from "firebase-admin";

var serviceAccount = require(process.env.FBPATH!)
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
export default admin;
