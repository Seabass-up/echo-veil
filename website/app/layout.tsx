import type { Metadata, Viewport } from "next";
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
  title: "Echo Veil v0.7.0 — Protected Semantic Memory for AI Agents",
  description:
    "Four-layer protected semantic memory for AI agents with answerability checks, visible ambiguity, fail-closed host gates, and a read-only outage layer.",
  alternates: { canonical: "/" },
  robots: { index: true, follow: true },
  openGraph: {
    title: "Echo Veil v0.7.0 — Memory that knows what to keep",
    description:
      "Four-layer protected semantic memory with answerability checks, fail-closed host gates, and an always-available read-only layer.",
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
    title: "Echo Veil v0.7.0 — Memory that knows what to keep",
    description:
      "Four-layer protected semantic memory with answerability checks, fail-closed host gates, and an always-available read-only layer.",
    images: ["/og.png"],
  },
};

export const viewport: Viewport = {
  colorScheme: "light",
  themeColor: "#0b1822",
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
