import { NextRequest, NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase/client";

// Simple in-memory rate limiter: max 3 contact submissions per IP per hour
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + 60 * 60 * 1000 });
    return true;
  }
  if (entry.count >= 3) return false;
  entry.count++;
  return true;
}

export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";

  if (!checkRateLimit(ip)) {
    return NextResponse.json({ error: "Too many messages. Please try again later." }, { status: 429 });
  }

  let body: { name?: string; email?: string; subject?: string; message?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const { name, email, subject, message } = body;

  if (!name?.trim() || !email?.trim() || !subject?.trim() || !message?.trim()) {
    return NextResponse.json({ error: "All fields are required." }, { status: 400 });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return NextResponse.json({ error: "Invalid email address." }, { status: 400 });
  }

  if (name.length > 100 || email.length > 200 || subject.length > 200 || message.length > 5000) {
    return NextResponse.json({ error: "One or more fields exceed the maximum length." }, { status: 400 });
  }

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db as any).from("contact_messages").insert({
    name: name.trim(),
    email: email.trim(),
    subject: subject.trim(),
    message: message.trim(),
  });

  if (error) {
    console.error("[Contact] DB insert error:", error);
    return NextResponse.json({ error: "Failed to send message. Please try again." }, { status: 500 });
  }

  return NextResponse.json({ success: true });
}
