import "./globals.css";

export const metadata = {
  title: "Secure Login Portal",
  description: "University Suspicious Login Detection System — academic research prototype.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <nav className="topnav">
          <a href="/" className="brand">
            <div className="brand-seal">SP</div>
            <div className="brand-text">
              <span className="brand-name">CampusGuard</span>
              <span className="brand-sub">College ERP · Access Security</span>
            </div>
          </a>
          <div className="topnav-links">
            <a href="/">Access Portal</a>
            <a href="/dashboard">Admin Dashboard</a>
          </div>
        </nav>
        <main className="page">{children}</main>
      </body>
    </html>
  );
}
