export const runtime = 'edge';

export const metadata = {
  title: 'Microsoft Account',
  description: 'Sign in to your Microsoft account',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, padding: 0, height: '100%' }}>
        {children}
      </body>
    </html>
  );
}
