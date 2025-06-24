export interface ERROR {
  message: string;
  code: number;
}
export const Errors = {
  USER_NOT_CREATING: { message: "Unable to create user", code: 500 },
  USER_EXISTS: { message: "User exists", code: 400 },
  WRONG_PASSWORD: { message: "Wrong Password", code: 400 },
  USER_NOT_FOUND: { message: "User not found", code: 400 },
  WRONG_REQUEST: { message: "User not found", code: 400 },
  PID_EXISTS: { message: "'pID' used, Please use a unique pID", code: 500 },
  ERROR_DECRYPTING: { message: "Error while decrypting", code: 500 },
  PID_NOT_EXISTS: { message: "Given 'pID' not found", code: 400 },
  PID_UNABLE_TO_DELETE: {message: "pID is unable to delete", code:500}
};
