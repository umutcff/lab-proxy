import { NextResponse } from "next/server";

export async function proxy(request) {
  // Optimistic check: is there any cookie that looks like our auth token?
  // (Checking common names since we can't inspect the backend directly)
  const hasToken =
    request.cookies.has("authToken") ||
    request.cookies.has("auth_token") ||
    request.cookies.has("token") ||
    request.cookies.has("session");

  // If no auth cookie is present, redirect immediately
  if (!hasToken) {
    return NextResponse.redirect(new URL("/auth", request.url));
  }

  // Secure check: validate the token with the backend
  try {
    const response = await fetch("http://localhost:8080/api/me", {
      headers: {
        // Forward the cookie header so the backend can read the token
        cookie: request.headers.get("cookie") || "",
      },
    });

    if (!response.ok) {
      // Token is invalid or expired
      return NextResponse.redirect(new URL("/auth", request.url));
    }

    const user = await response.json();

    // Enforce role for /admin
    if (request.nextUrl.pathname.startsWith("/admin") && user.role !== "ADMIN") {
      return NextResponse.redirect(new URL("/", request.url));
    }

    // Token is valid and role is allowed, proceed
    return NextResponse.next();
  } catch (error) {
    // If the backend is unreachable or fails, deny access
    return NextResponse.redirect(new URL("/auth", request.url));
  }
}

export const config = {
  matcher: ["/dashboard/:path*", "/admin/:path*"],
};
