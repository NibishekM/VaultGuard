export interface AuthenticatedUser {
  id: string;
  email: string;
}

export interface AuthenticatedSession {
  id: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
      session?: AuthenticatedSession;
    }
  }
}

