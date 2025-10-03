export const runtime = 'edge';

export default function Home() {
  // This page won't be visible since [...path] catches root
  // But it's required by Next.js app router
  return null;
}