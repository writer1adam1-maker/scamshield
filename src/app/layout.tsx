import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import { Sidebar } from "@/components/layout/sidebar";
import { InstallPrompt } from "@/components/pwa/install-prompt";
import "./globals.css";

const inter = Inter({
  variable: "--font-sans",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "ScamShieldy - Is This Legit or Am I About to Get Screwed?",
  description:
    "AI-powered scam detection. Paste a URL, email, or text message and get an instant threat analysis with evidence-backed scoring.",
  icons: { icon: "/favicon.ico" },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <meta name="theme-color" content="#0a0a0f" />
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
        {/* Apply saved theme before first paint to avoid flash */}
        <script dangerouslySetInnerHTML={{ __html: `(function(){try{var t=localStorage.getItem('theme')||'dark';document.documentElement.setAttribute('data-theme',t);}catch(e){}if('serviceWorker' in navigator){window.addEventListener('load',function(){navigator.serviceWorker.register('/sw.js')})}})()` }} />
      </head>
      <body
        className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased bg-void text-text-primary min-h-screen`}
      >
        {/* Subtle hex grid overlay across the whole viewport */}
        <div className="fixed inset-0 hex-grid-bg opacity-[0.04] pointer-events-none" />

        {/* Faint radial glow behind the center of the page */}
        <div className="fixed inset-0 pointer-events-none">
          <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[800px] h-[800px] rounded-full bg-shield/[0.03] blur-[120px]" />
        </div>

        <div className="relative flex min-h-screen">
          <Sidebar />
          <main className="flex-1 ml-0 md:ml-64 min-h-screen">
            <div className="p-4 md:p-8 max-w-6xl mx-auto">{children}</div>
          </main>
        </div>
        <InstallPrompt />
      </body>
    </html>
  );
}
