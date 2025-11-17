import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import postgres from 'postgres';
import { authConfig } from './auth.config';
import type { User } from '@/app/lib/definitions';

// Initialize PostgreSQL connection
const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

// Helper function to fetch a user by email
async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'email' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        // Validate credentials format
        const parsed = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (!parsed.success) return null; // invalid input

        const { email, password } = parsed.data;

        // Fetch user from database
        const user = await getUser(email);
        if (!user) return null; // user not found

        // Compare password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return null; // wrong password

        // Success: return user object
        return user;
      },
    }),
  ],
  pages: {
    signIn: '/login',
  },
});
