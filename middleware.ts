import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"
import { getToken } from "next-auth/jwt"

// Routes that require authentication
const protectedPrefixes = ["/dashboard"]
// Routes only accessible when NOT authenticated
const authRoutes = ["/login", "/signup"]

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  const isProtected = protectedPrefixes.some((prefix) => pathname.startsWith(prefix))
  const isAuthRoute = authRoutes.some((route) => pathname.startsWith(route))

  // In Vercel Edge, NEXTAUTH_URL sometimes gets confused about https.
  // We explicitly check if it's running in production to know which cookie to look for.
  const isProduction = process.env.NODE_ENV === "production";

  const token = await getToken({
    req: request,
    secret: process.env.NEXTAUTH_SECRET,
    // This forces it to look for the __Secure- prefix when on Vercel
    secureCookie: isProduction,
  })

  // If getToken STILL fails due to proxy issues, check the cookie manually as a fallback
  const fallbackToken = request.cookies.get(
    isProduction ? '__Secure-next-auth.session-token' : 'next-auth.session-token'
  );

  const isAuthenticated = !!token || !!fallbackToken;

  // Redirect unauthenticated users away from protected routes
  if (isProtected && !isAuthenticated) {
    const loginUrl = new URL("/login", request.url)
    loginUrl.searchParams.set("callbackUrl", pathname)
    return NextResponse.redirect(loginUrl)
  }

  // Redirect authenticated users away from login/signup
  if (isAuthRoute && isAuthenticated) {
    return NextResponse.redirect(new URL("/dashboard", request.url))
  }

  return NextResponse.next()
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|api/auth).*)",
  ],
}