import type { Metadata, Viewport } from 'next'
import './globals.css'
import '@/components/vaultguard/command-center.css'
import { VaultProvider } from '@/lib/crypto/vault-context'
import { AuthProvider } from '@/lib/auth/auth-context'

export const metadata: Metadata = {
  title: 'VaultGuard — Personal Security',
  description: 'Explore VaultGuard’s frontend security demo: analyze password strength locally, generate strong passphrases, and review fictional vault records.',
  generator: 'v0.app',
  icons: { icon: '/icon.svg', apple: '/apple-icon.png' },
}

export const viewport: Viewport = {
  colorScheme: 'dark',
  themeColor: '#080D14',
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="antialiased">
        <AuthProvider>
          <VaultProvider>{children}</VaultProvider>
        </AuthProvider>
      </body>
    </html>
  )
}
