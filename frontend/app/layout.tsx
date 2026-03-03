import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Attack Surface Monitor",
  description: "AI-powered attack surface monitoring and reconnaissance",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-background text-freeze antialiased">
        {children}
      </body>
    </html>
  );
}
