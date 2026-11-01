import { timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

export function isAuthorized(authHeader: string | undefined, expected: string): boolean {
  if (!authHeader) return false;

  const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
  if (!match?.[1]) return false;

  const provided = Buffer.from(match[1]);
  const reference = Buffer.from(expected);
  if (provided.length !== reference.length) return false;

  return timingSafeEqual(provided, reference);
}

export function bearerAuth(expected: string): RequestHandler {
  return (request: Request, response: Response, next: NextFunction): void => {
    if (isAuthorized(request.headers.authorization, expected)) {
      next();
      return;
    }
    response.status(401).json({ error: 'unauthorized' });
  };
}
