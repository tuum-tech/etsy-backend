// express.d.ts

import expressSession from 'express-session'

declare module 'express' {
  export interface Request {
    session: expressSession.Session &
      Partial<expressSession.SessionData> &
      CustomSession
  }
}

interface CustomSession extends Express.Session {
  state?: string
}
