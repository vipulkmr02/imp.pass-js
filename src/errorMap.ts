export interface ERROR {
  message: string;
  code: number;
}
export const ERRORS = {
  CANT_CREATE_USER: { message: "Unable to create user", code: 500 },
  PASSWORDS_DO_NOT_MATCH: { message: "Passwords do not match", code: 400 },
  USER_EXISTS: { message: "User exists", code: 400 },
  WRONG_PASSWORD: { message: "Wrong Password", code: 400 },
  USER_NOT_FOUND: { message: "User not found", code: 400 },
  WRONG_REQUEST: { message: "Wrong Request", code: 400 },
  PID_EXISTS: { message: "'pID' used, Please use a unique pID", code: 500 },
  ERROR_DECRYPTING: { message: "Error while decrypting", code: 500 },
  PID_NOT_EXISTS: { message: "Given 'pID' not found", code: 400 },
  PID_UNABLE_TO_DELETE: { message: "Unable to delete pID", code: 500 },
  INVALID_SESSION_ID: { message: "Session ID is invalid", code: 400 },
  SESSION_EXPIRED: { message: "Session Expired", code: 401 }
};
