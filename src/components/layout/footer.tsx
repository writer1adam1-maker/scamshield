import Link from "next/link";

export function Footer() {
  return (
    <footer className="mt-16 pt-6 border-t border-white/5">
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono text-text-muted">
        <p>© {new Date().getFullYear()} ScamShieldy. All rights reserved.</p>
        <nav className="flex items-center gap-4">
          <Link href="/contact" className="hover:text-text-secondary transition-colors">
            Contact Us
          </Link>
          <span className="text-white/10">|</span>
          <Link href="/privacy" className="hover:text-text-secondary transition-colors">
            Privacy Policy
          </Link>
          <span className="text-white/10">|</span>
          <Link href="/terms" className="hover:text-text-secondary transition-colors">
            Terms of Service
          </Link>
        </nav>
      </div>
    </footer>
  );
}
