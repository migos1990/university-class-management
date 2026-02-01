const { initializeDatabase, isDatabaseSeeded } = require('../config/database');
const { seedDatabase } = require('../utils/seedData');
const selfsigned = require('selfsigned');
const fs = require('fs');
const path = require('path');

console.log('='.repeat(60));
console.log('University Class Management System - Setup');
console.log('='.repeat(60));
console.log('');

// Step 1: Initialize database schema
console.log('[1/3] Initializing database schema...');
try {
  initializeDatabase();
  console.log('✓ Database schema created successfully');
} catch (error) {
  console.error('✗ Error initializing database:', error.message);
  process.exit(1);
}

// Step 2: Seed database if not already seeded
console.log('\n[2/3] Checking database data...');
if (!isDatabaseSeeded()) {
  console.log('Seeding database with sample data...');
  try {
    seedDatabase();
    console.log('✓ Database seeded successfully');
  } catch (error) {
    console.error('✗ Error seeding database:', error.message);
    process.exit(1);
  }
} else {
  console.log('✓ Database already contains data (skipping seed)');
}

// Step 3: Generate SSL certificates
console.log('\n[3/3] Generating SSL certificates...');
const sslDir = path.join(__dirname, '..', 'ssl');
const certPath = path.join(sslDir, 'server-cert.pem');
const keyPath = path.join(sslDir, 'server-key.pem');

// Create ssl directory if it doesn't exist
if (!fs.existsSync(sslDir)) {
  fs.mkdirSync(sslDir, { recursive: true });
}

// Check if certificates already exist
if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
  console.log('✓ SSL certificates already exist (skipping generation)');
} else {
  try {
    const attrs = [{ name: 'commonName', value: 'localhost' }];
    const pems = selfsigned.generate(attrs, {
      keySize: 2048,
      days: 365,
      algorithm: 'sha256',
      extensions: [
        {
          name: 'subjectAltName',
          altNames: [
            { type: 2, value: 'localhost' },
            { type: 7, ip: '127.0.0.1' }
          ]
        }
      ]
    });

    fs.writeFileSync(certPath, pems.cert);
    fs.writeFileSync(keyPath, pems.private);
    console.log('✓ SSL certificates generated successfully');
  } catch (error) {
    console.error('✗ Error generating SSL certificates:', error.message);
    process.exit(1);
  }
}

console.log('');
console.log('='.repeat(60));
console.log('Setup completed successfully!');
console.log('='.repeat(60));
console.log('');
console.log('Next step: Run "npm start" to start the application');
console.log('Then open http://localhost:3000 in your browser');
console.log('');
console.log('Default login:');
console.log('  Admin:     admin / admin123');
console.log('  Professor: prof_jones / prof123');
console.log('  Student:   alice_student / student123');
console.log('');
