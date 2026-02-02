const fs = require('fs');
const path = require('path');
const { db } = require('../config/database');

const BACKUP_DIR = path.join(__dirname, '..', 'backups');
let backupInterval = null;

/**
 * Ensure backup directory exists
 */
function ensureBackupDir() {
  if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    console.log('✓ Backup directory created:', BACKUP_DIR);
  }
}

/**
 * Create a backup of the database
 */
function createBackup() {
  try {
    ensureBackupDir();

    // Create timestamp in format: YYYY-MM-DD-HHMMSS
    const now = new Date();
    const timestamp = now.toISOString()
      .replace(/[:.]/g, '-')
      .replace('T', '-')
      .split('.')[0]; // Remove milliseconds

    const filename = `backup-${timestamp}.json`;
    const filepath = path.join(BACKUP_DIR, filename);

    // Read current database file
    const dbPath = path.join(__dirname, '..', 'database', 'data.json');

    if (!fs.existsSync(dbPath)) {
      return { success: false, error: 'Database file not found' };
    }

    const dbData = fs.readFileSync(dbPath, 'utf8');

    // Write backup
    fs.writeFileSync(filepath, dbData, 'utf8');

    console.log(`✓ Backup created: ${filename}`);

    // Update last backup time in settings
    try {
      db.prepare(`
        UPDATE security_settings
        SET last_backup_time = ?
        WHERE id = 1
      `).run(now.toISOString());
    } catch (error) {
      console.warn('Could not update last_backup_time:', error.message);
    }

    return { success: true, filename, filepath, size: Buffer.byteLength(dbData, 'utf8') };
  } catch (error) {
    console.error('Backup error:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Get list of all backups
 */
function listBackups() {
  ensureBackupDir();

  try {
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('backup-') && f.endsWith('.json'))
      .map(filename => {
        const filepath = path.join(BACKUP_DIR, filename);
        const stats = fs.statSync(filepath);
        return {
          filename,
          filepath,
          size: stats.size,
          created: stats.mtime
        };
      })
      .sort((a, b) => b.created - a.created); // Most recent first

    return files;
  } catch (error) {
    console.error('Error listing backups:', error);
    return [];
  }
}

/**
 * Restore database from backup
 */
function restoreBackup(filename) {
  try {
    const backupPath = path.join(BACKUP_DIR, filename);

    if (!fs.existsSync(backupPath)) {
      throw new Error('Backup file not found');
    }

    const dbPath = path.join(__dirname, '..', 'database', 'data.json');
    const backupData = fs.readFileSync(backupPath, 'utf8');

    // Validate JSON before restoring
    JSON.parse(backupData);

    // Create safety backup of current state before restoring
    const safetyBackup = `backup-before-restore-${Date.now()}.json`;
    if (fs.existsSync(dbPath)) {
      const currentData = fs.readFileSync(dbPath, 'utf8');
      fs.writeFileSync(path.join(BACKUP_DIR, safetyBackup), currentData, 'utf8');
      console.log(`✓ Safety backup created: ${safetyBackup}`);
    }

    // Restore
    fs.writeFileSync(dbPath, backupData, 'utf8');

    console.log(`✓ Database restored from: ${filename}`);

    return { success: true, safetyBackup };
  } catch (error) {
    console.error('Restore error:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Start backup scheduling
 */
function startBackupSchedule(frequencyMinutes) {
  stopBackupSchedule(); // Clear any existing schedule

  if (!frequencyMinutes || frequencyMinutes < 5) {
    console.warn('Invalid backup frequency. Must be at least 5 minutes.');
    return false;
  }

  const intervalMs = frequencyMinutes * 60 * 1000;

  backupInterval = setInterval(() => {
    console.log('Running scheduled backup...');
    const result = createBackup();
    if (result.success) {
      cleanupOldBackups(50); // Keep only last 50 backups
    }
  }, intervalMs);

  console.log(`✓ Backup schedule started: Every ${frequencyMinutes} minutes`);
  return true;
}

/**
 * Stop backup scheduling
 */
function stopBackupSchedule() {
  if (backupInterval) {
    clearInterval(backupInterval);
    backupInterval = null;
    console.log('✓ Backup schedule stopped');
    return true;
  }
  return false;
}

/**
 * Delete old backups (keep only last N)
 */
function cleanupOldBackups(keepCount = 50) {
  const backups = listBackups();

  if (backups.length > keepCount) {
    const toDelete = backups.slice(keepCount);
    let deletedCount = 0;

    toDelete.forEach(backup => {
      // Don't delete safety backups
      if (backup.filename.includes('before-restore')) {
        return;
      }

      try {
        fs.unlinkSync(backup.filepath);
        deletedCount++;
      } catch (error) {
        console.error(`Error deleting ${backup.filename}:`, error);
      }
    });

    console.log(`✓ Cleaned up ${deletedCount} old backups (keeping last ${keepCount})`);
    return deletedCount;
  }

  return 0;
}

/**
 * Initialize backup system on server start
 */
function initializeBackupSystem() {
  try {
    ensureBackupDir();

    const settings = db.prepare('SELECT * FROM security_settings WHERE id = 1').get();

    if (settings && settings.backup_enabled) {
      const frequency = settings.backup_frequency || 60;
      startBackupSchedule(frequency);
      console.log(`✓ Backup system initialized (frequency: ${frequency} minutes)`);
    } else {
      console.log('ℹ Backup system ready (currently disabled)');
    }
  } catch (error) {
    console.error('Error initializing backup system:', error.message);
  }
}

module.exports = {
  createBackup,
  listBackups,
  restoreBackup,
  startBackupSchedule,
  stopBackupSchedule,
  cleanupOldBackups,
  initializeBackupSystem,
  ensureBackupDir
};
