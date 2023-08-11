import 'express-session'

declare module 'express-session' {
  export interface SessionData {
    state: string
    codeVerifier: string
    // any other properties or data types you'd like to add
  }
}
