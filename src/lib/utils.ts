import { NextRequest } from "next/server";

/**
 * Extract the client IP address from the request headers.
 * Falls back to 127.0.0.1 if no forwarding headers are present.
 */
export function getClientIp(req: NextRequest): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "127.0.0.1"
  );
}
