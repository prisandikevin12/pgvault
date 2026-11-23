import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PGVault — Encrypted PostgreSQL Backup & Restore Verification",
  description:
    "Manage encrypted PostgreSQL backup targets, trigger backup jobs, monitor automated restore verification, and configure Telegram alerts.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
