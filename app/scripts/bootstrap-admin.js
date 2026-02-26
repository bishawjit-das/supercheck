/**
 * Bootstrap Super Admin
 *
 * 1) If ADMIN_EMAIL, ADMIN_NAME, ADMIN_PASSWORD are set and no super admin exists:
 *    creates the user (with Better Auth–compatible password hash) and sets role to super_admin.
 * 2) Otherwise: promotes an existing user to super_admin (CLI arg or SUPER_ADMIN_EMAIL).
 *
 * Usage:
 *   node scripts/bootstrap-admin.js [email]
 *   OR set SUPER_ADMIN_EMAIL env var (promote existing user)
 *   OR set ADMIN_EMAIL, ADMIN_NAME, ADMIN_PASSWORD (create + promote on first run)
 */

require('dotenv').config();
const postgres = require('postgres');
const crypto = require('crypto');
const { promisify } = require('util');

const scryptAsync = promisify(crypto.scrypt);

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return scryptAsync(password, salt, 64).then((buf) => `${buf.toString('hex')}.${salt}`);
}

async function main() {
  const adminEmailFromEnv = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const adminName = process.env.ADMIN_NAME?.trim();
  const adminPassword = process.env.ADMIN_PASSWORD;
  const adminEmailInput = process.argv[2] || process.env.SUPER_ADMIN_EMAIL?.trim().toLowerCase() || adminEmailFromEnv;
  const adminEmail = adminEmailInput?.toLowerCase();

  if (!adminEmail) {
    console.log('ℹ️  No email provided (ADMIN_EMAIL, SUPER_ADMIN_EMAIL, or CLI). Skipping admin bootstrap.');
    return;
  }

  if (adminEmail.includes(',')) {
    console.error('❌ Error: Email must be a single address, not a list.');
    process.exit(1);
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(adminEmail)) {
    console.error('❌ Error: Invalid email format.');
    process.exit(1);
  }

  if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL is not set. Cannot bootstrap admin.');
    process.exit(1);
  }

  const createIfMissing = adminName && adminPassword && adminEmailFromEnv === adminEmail;

  console.log(`🔐 Bootstrapping super admin for: ${adminEmail}`);

  const sql = postgres(process.env.DATABASE_URL, {
    ssl: process.env.DATABASE_SSL === 'true' ? 'require' : false,
    max: 1
  });

  try {
    const existingAdmins = await sql`
      SELECT email FROM "user" WHERE role = 'super_admin' LIMIT 1
    `;

    if (existingAdmins.length > 0) {
      const existingEmail = existingAdmins[0].email;
      if (existingEmail === adminEmail) {
        console.log(`✅ User ${adminEmail} is already the super admin.`);
        return;
      }
      console.error(`❌ Error: A super admin already exists (${existingEmail}).`);
      console.error('   System allows only ONE super admin.');
      process.exit(1);
    }

    let users = await sql`
      SELECT id FROM "user" WHERE LOWER(email) = ${adminEmail} LIMIT 1
    `;

    if (users.length === 0) {
      if (!createIfMissing) {
        console.log(`⚠️  User ${adminEmail} not found. Set ADMIN_EMAIL, ADMIN_NAME, ADMIN_PASSWORD to create on first run, or have them sign up first.`);
        return;
      }
      const hashedPassword = await hashPassword(adminPassword);
      const now = new Date();
      const newUser = await sql`
        INSERT INTO "user" (id, name, email, email_verified, created_at, updated_at, role)
        VALUES (gen_random_uuid(), ${adminName}, ${adminEmail}, true, ${now}, ${now}, 'super_admin')
        RETURNING id
      `;
      const userId = newUser[0].id;
      await sql`
        INSERT INTO account (id, provider_id, user_id, password, created_at, updated_at)
        VALUES (gen_random_uuid(), 'credential', ${userId}, ${hashedPassword}, ${now}, ${now})
      `;
      console.log(`✅ Created ${adminEmail} and set as super_admin.`);
      return;
    }

    await sql`
      UPDATE "user" SET role = 'super_admin' WHERE id = ${users[0].id}
    `;
    console.log(`✅ Successfully promoted ${adminEmail} to super_admin.`);
  } catch (error) {
    console.error('❌ Error bootstrapping super admin:', error);
    process.exit(1);
  } finally {
    await sql.end();
  }
}

main();
