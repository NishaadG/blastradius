import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans, Newsreader } from "next/font/google";
import "./globals.css";

const plex = IBM_Plex_Sans({ variable: "--font-plex", subsets: ["latin"], weight: ["400", "500", "600"] });
const plexMono = IBM_Plex_Mono({ variable: "--font-plex-mono", subsets: ["latin"], weight: ["400", "500", "600"] });
const newsreader = Newsreader({ variable: "--font-newsreader", subsets: ["latin"], style: ["normal", "italic"] });

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
    <html lang="en" className={`${plex.variable} ${plexMono.variable} ${newsreader.variable} h-full`}>
      <body className="h-full">{children}</body>
    </html>
  );
}
