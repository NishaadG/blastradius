import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({ variable: "--font-inter", subsets: ["latin"] });
const jetbrains = JetBrains_Mono({ variable: "--font-jetbrains", subsets: ["latin"] });

const description =
  "Supply-chain vulnerability triage agent with a FalkorDB graph brain: paths, blast radius, memory and proof.";

export const metadata: Metadata = {
  title: "Blastradius",
  description,
  openGraph: { title: "Blastradius", description, type: "website" },
  twitter: { card: "summary", title: "Blastradius", description },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrains.variable} h-full antialiased`}>
      <body className="h-full">{children}</body>
    </html>
  );
}
