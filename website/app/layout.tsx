import type { Metadata } from "next";
import { DM_Mono, Manrope } from "next/font/google";
import "./globals.css";

const manrope = Manrope({
  variable: "--font-manrope",
  subsets: ["latin"],
});

const dmMono = DM_Mono({
  variable: "--font-dm-mono",
  subsets: ["latin"],
  weight: ["400", "500"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://echo.algo-cli.com"),
  title: "Echo Veil — A Wiser Memory for AI Agents",
  description:
    "A privacy-first, intent-driven memory layer for AI agents that keeps active context sharp, preserves contradictions, and makes uncertainty visible.",
  openGraph: {
    title: "Echo Veil — Memory that knows what to keep",
    description:
      "A living memory layer for AI agents. Intent-driven, privacy-first, and honest about uncertainty.",
    type: "website",
    url: "https://echo.algo-cli.com",
    siteName: "Echo Veil",
    images: [
      {
        url: "/og.png",
        width: 1200,
        height: 630,
        alt: "Echo Veil — Memory that knows what to keep",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Echo Veil — Memory that knows what to keep",
    description:
      "A living memory layer for AI agents. Intent-driven, privacy-first, and honest about uncertainty.",
    images: ["/og.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${manrope.variable} ${dmMono.variable}`}>
        {children}
      </body>
    </html>
  );
}
