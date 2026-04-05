import Link from 'next/link'

export default function NotFound() {
  return (
    <div className="min-h-screen bg-abyss flex items-center justify-center px-4">
      <div className="glass-card max-w-md w-full p-10 text-center rounded-2xl">
        {/* Shield icon with 404 */}
        <div className="flex justify-center mb-6">
          <div className="relative">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 64 64"
              className="w-24 h-24 text-shield"
              fill="currentColor"
            >
              <path d="M32 2L6 13v18c0 14.4 11.1 27.9 26 31 14.9-3.1 26-16.6 26-31V13L32 2z" opacity="0.15" />
              <path
                d="M32 2L6 13v18c0 14.4 11.1 27.9 26 31 14.9-3.1 26-16.6 26-31V13L32 2z"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinejoin="round"
              />
            </svg>
            <span className="absolute inset-0 flex items-center justify-center text-shield font-bold text-xl tracking-tight">
              404
            </span>
          </div>
        </div>

        {/* Title */}
        <h1 className="text-2xl font-bold text-text-primary mb-3">
          Page Not Found
        </h1>

        {/* Subtitle */}
        <p className="text-text-primary/60 text-sm mb-8">
          This page doesn&apos;t exist or has been moved.
        </p>

        {/* Go Home button */}
        <Link
          href="/"
          className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-shield text-white font-medium text-sm hover:bg-shield/90 transition-colors duration-200"
        >
          Go Home
        </Link>
      </div>
    </div>
  )
}
