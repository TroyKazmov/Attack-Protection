import fs from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';

// Define project structure with all files
const projectName = 'enhanced-botnet-protection';
const projectStructure = {
  'package.json': `{
  "name": "enhanced-botnet-protection",
  "version": "1.0.0",
  "description": "Enhanced botnet protection implementation with monitoring",
  "main": "dist/server.js",
  "scripts": {
    "build": "tsc",
    "start": "node dist/server.js",
    "dev": "ts-node src/server.ts",
    "test": "jest"
  },
  "keywords": ["security", "botnet", "protection", "cybersecurity"],
  "author": "",
  "license": "ISC",
  "devDependencies": {
    "@types/express": "^4.17.17",
    "@types/jest": "^29.5.0",
    "@types/node": "^18.15.11",
    "@types/node-cron": "^3.0.7",
    "@types/supertest": "^2.0.12",
    "jest": "^29.5.0",
    "supertest": "^6.3.3",
    "ts-jest": "^29.1.0",
    "ts-node": "^10.9.1",
    "typescript": "^5.0.4"
  },
  "dependencies": {
    "axios": "^1.3.5",
    "chart.js": "^4.2.1",
    "dotenv": "^16.0.3",
    "express": "^4.18.2",
    "node-cron": "^3.0.2",
    "pug": "^3.0.2",
    "winston": "^3.8.2"
  }
}`,
  'tsconfig.json': `{
  "compilerOptions": {
    "target": "es2020",
    "module": "commonjs",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src/**/*"]
}`,
  '.env.example': `# Server configuration
# Change the port if needed, especially if port 3000 is already in use
PORT=3000
NODE_ENV=development

# Security settings
# Adjust these values based on your traffic patterns
# RATE_LIMIT_THRESHOLD: Maximum number of requests allowed per time window
# RATE_LIMIT_WINDOW_MS: Time window in milliseconds (60000 = 1 minute)
# IP_BLOCKLIST_UPDATE_INTERVAL: How often to update IP blocklists (86400000 = 24 hours)
RATE_LIMIT_THRESHOLD=100
RATE_LIMIT_WINDOW_MS=60000
IP_BLOCKLIST_UPDATE_INTERVAL=86400000

# Dashboard access credentials
# IMPORTANT: Change these values before deploying to production!
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme
`,
  'src/config.ts': `import dotenv from 'dotenv';
import path from 'path';

// Load environment variables from .env file
dotenv.config();

/**
 * Application configuration
 * 
 * This object contains all configuration settings for the application.
 * Values are loaded from environment variables with fallbacks to defaults.
 * 
 * CUSTOMIZATION:
 * - To change any settings, modify the .env file rather than changing this file
 * - For development, copy .env.example to .env and adjust values as needed
 */
export const config = {
  server: {
    // Server port - change in .env if needed
    port: parseInt(process.env.PORT || '3000', 10),
    env: process.env.NODE_ENV || 'development',
  },
  security: {
    // Security thresholds - adjust these based on your traffic patterns
    rateLimitThreshold: parseInt(process.env.RATE_LIMIT_THRESHOLD || '100', 10),
    rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
    ipBlocklistUpdateInterval: parseInt(process.env.IP_BLOCKLIST_UPDATE_INTERVAL || '86400000', 10),
  },
  dashboard: {
    // Dashboard access credentials - CHANGE THESE in .env for security!
    adminUsername: process.env.ADMIN_USERNAME || 'admin',
    adminPassword: process.env.ADMIN_PASSWORD || 'changeme',
  },
  paths: {
    // File system paths for logs and data storage
    logs: path.join(process.cwd(), 'logs'),
    data: path.join(process.cwd(), 'data'),
  }
};
`,
  'src/utils/logger.ts': `import winston from 'winston';
import fs from 'fs';
import path from 'path';
import { config } from '../config';

/**
 * Logger Configuration
 * 
 * This module sets up logging for the application using Winston.
 * Logs are written to both console and files.
 * 
 * CUSTOMIZATION:
 * - To add email notifications for security events, add an email transport
 * - To change log formats or levels, modify the logFormat and level settings
 */

// Ensure logs directory exists
if (!fs.existsSync(config.paths.logs)) {
  fs.mkdirSync(config.paths.logs, { recursive: true });
}

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.json()
);

// Create logger
export const logger = winston.createLogger({
  level: config.server.env === 'production' ? 'info' : 'debug',
  format: logFormat,
  defaultMeta: { service: 'botnet-protection' },
  transports: [
    // Console transport
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
    // File transport for all logs
    new winston.transports.File({ 
      filename: path.join(config.paths.logs, 'combined.log') 
    }),
    // File transport for error logs
    new winston.transports.File({ 
      filename: path.join(config.paths.logs, 'error.log'),
      level: 'error'
    }),
    // File transport for security events
    new winston.transports.File({ 
      filename: path.join(config.paths.logs, 'security.log'),
      level: 'warn'
    })
  ],
});

/**
 * Log security events
 * 
 * Use this function to log security-related events like blocked IPs,
 * detected bots, etc. These logs will appear in the security.log file
 * and will be visible in the dashboard.
 * 
 * @param eventType - Type of security event (e.g., 'BLOCKED_REQUEST', 'BOT_DETECTED')
 * @param ip - IP address associated with the event
 * @param details - Additional details about the event
 */
export const logSecurityEvent = (
  eventType: string, 
  ip: string, 
  details: Record<string, any>
) => {
  logger.warn({
    eventType,
    ip,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// CUSTOMIZATION POINT: Add email alerts for critical security events
/*
import nodemailer from 'nodemailer';

// Configure email transport (uncomment and configure to enable email alerts)
const transporter = nodemailer.createTransport({
  host: 'smtp.example.com',
  port: 587,
  secure: false,
  auth: {
    user: 'your-email@example.com',
    pass: 'your-password'
  }
});

// Send email alert for critical security events
export const sendSecurityAlert = async (eventType: string, details: any) => {
  await transporter.sendMail({
    from: 'security@yourdomain.com',
    to: 'admin@yourdomain.com',
    subject: \`Security Alert: \${eventType}\`,
    text: JSON.stringify(details, null, 2)
  });
};
*/
`,
  'src/security/rate-limiter.ts': `import { logSecurityEvent } from '../utils/logger';
import { config } from '../config';

/**
 * Rate Limiter
 * 
 * This class implements rate limiting to prevent abuse from individual IP addresses.
 * It tracks requests per IP and blocks IPs that exceed configured thresholds.
 * 
 * CUSTOMIZATION:
 * - Adjust threshold, timeWindow, and blockDuration in the constructor or via .env
 * - Add whitelist functionality for trusted IPs if needed
 */
export class RateLimiter {
  private requests: Map<string, number[]> = new Map();
  private blockedIPs: Set<string> = new Set();
  private threshold: number;
  private timeWindow: number;
  private blockDuration: number;

  /**
   * Create a new RateLimiter
   * 
   * @param threshold - Maximum number of requests allowed in the time window
   * @param timeWindow - Time window in milliseconds
   * @param blockDuration - How long to block IPs in milliseconds
   */
  constructor(
    threshold = config.security.rateLimitThreshold,
    timeWindow = config.security.rateLimitWindowMs,
    blockDuration = 3600000 // 1 hour block by default
  ) {
    this.threshold = threshold;
    this.timeWindow = timeWindow;
    this.blockDuration = blockDuration;
  }

  /**
   * Check if an IP is rate limited
   * 
   * @param ip - IP address to check
   * @returns true if the IP should be blocked, false otherwise
   */
  isRateLimited(ip: string): boolean {
    const now = Date.now();
    
    // Check if IP is currently blocked
    if (this.blockedIPs.has(ip)) {
      logSecurityEvent('BLOCKED_REQUEST', ip, { reason: 'IP is blocked' });
      return true;
    }
    
    if (!this.requests.has(ip)) {
      this.requests.set(ip, [now]);
      return false;
    }

    const requests = this.requests.get(ip)!;
    
    // Remove old requests outside the time window
    const recentRequests = requests.filter(time => now - time < this.timeWindow);
    this.requests.set(ip, recentRequests);
    
    // Check if request count exceeds threshold
    if (recentRequests.length >= this.threshold) {
      // Block the IP temporarily
      this.blockIP(ip);
      
      logSecurityEvent('RATE_LIMIT_EXCEEDED', ip, { 
        requestCount: recentRequests.length,
        threshold: this.threshold,
        timeWindow: this.timeWindow
      });
      
      return true;
    }
    
    // Add current request timestamp
    recentRequests.push(now);
    return false;
  }
  
  /**
   * Block an IP address for a specified duration
   * 
   * @param ip - IP address to block
   * @param duration - Duration to block in milliseconds (defaults to blockDuration)
   */
  blockIP(ip: string, duration = this.blockDuration): void {
    this.blockedIPs.add(ip);
    
    // Unblock after duration
    setTimeout(() => {
      this.blockedIPs.delete(ip);
      logSecurityEvent('IP_UNBLOCKED', ip, { reason: 'Block duration expired' });
    }, duration);
    
    logSecurityEvent('IP_BLOCKED', ip, { 
      reason: 'Rate limit exceeded',
      duration: duration
    });
  }
  
  /**
   * Get statistics about rate limiting
   * 
   * @returns Object with totalTracked and currentlyBlocked counts
   */
  getStats(): { totalTracked: number, currentlyBlocked: number } {
    return {
      totalTracked: this.requests.size,
      currentlyBlocked: this.blockedIPs.size
    };
  }
  
  /**
   * Get a list of currently blocked IPs
   * 
   * @returns Array of blocked IP addresses
   */
  getBlockedIPs(): string[] {
    return Array.from(this.blockedIPs);
  }
}

// Create singleton instance
export const rateLimiter = new RateLimiter();
`,
  'src/security/ip-blocklist.ts': `import fs from 'fs';
import path from 'path';
import axios from 'axios';
import cron from 'node-cron';
import { config } from '../config';
import { logger, logSecurityEvent } from '../utils/logger';

/**
 * IP Blocklist Manager
 * 
 * This class manages a list of blocked IP addresses.
 * It can load/save blocklists from disk and update from external sources.
 * 
 * CUSTOMIZATION:
 * - Add your own threat intelligence feeds in updateFromPublicSources()
 * - Implement whitelist functionality if needed
 * - Add methods to export/import blocklists in different formats
 */
export class IPBlocklist {
  private blocklist: Set<string> = new Set();
  private dataPath: string;
  
  constructor() {
    // Ensure data directory exists
    if (!fs.existsSync(config.paths.data)) {
      fs.mkdirSync(config.paths.data, { recursive: true });
    }
    
    this.dataPath = path.join(config.paths.data, 'ip-blocklist.json');
    
    // Load existing blocklist if available
    this.loadBlocklist();
    
    // Schedule regular updates
    this.scheduleUpdates();
  }
  
  /**
   * Check if an IP is in the blocklist
   * 
   * @param ip - IP address to check
   * @returns true if the IP is blocked, false otherwise
   */
  isBlocked(ip: string): boolean {
    return this.blocklist.has(ip);
  }
  
  /**
   * Add an IP to the blocklist
   * 
   * @param ip - IP address to block
   */
  addIP(ip: string): void {
    this.blocklist.add(ip);
    this.saveBlocklist();
    logSecurityEvent('IP_ADDED_TO_BLOCKLIST', ip, { source: 'manual' });
  }
  
  /**
   * Remove an IP from the blocklist
   * 
   * @param ip - IP address to unblock
   */
  removeIP(ip: string): void {
    this.blocklist.delete(ip);
    this.saveBlocklist();
    logger.info(\`Removed IP \${ip} from blocklist\`);
  }
  
  /**
   * Get all blocked IPs
   * 
   * @returns Array of blocked IP addresses
   */
  getBlockedIPs(): string[] {
    return Array.from(this.blocklist);
  }
  
  /**
   * Load blocklist from disk
   * 
   * @private
   */
  private loadBlocklist(): void {
    try {
      if (fs.existsSync(this.dataPath)) {
        const data = fs.readFileSync(this.dataPath, 'utf8');
        const ips = JSON.parse(data);
        this.blocklist = new Set(ips);
        logger.info(\`Loaded \${this.blocklist.size} IPs from blocklist\`);
      }
    } catch (error) {
      logger.error('Error loading IP blocklist:', error);
    }
  }
  
  /**
   * Save blocklist to disk
   * 
   * @private
   */
  private saveBlocklist(): void {
    try {
      const ips = Array.from(this.blocklist);
      fs.writeFileSync(this.dataPath, JSON.stringify(ips, null, 2));
    } catch (error) {
      logger.error('Error saving IP blocklist:', error);
    }
  }
  
  /**
   * Schedule regular updates of the blocklist
   * 
   * @private
   */
  private scheduleUpdates(): void {
    // Update once a day (at midnight)
    cron.schedule('0 0 * * *', () => {
      this.updateFromPublicSources();
    });
    
    // Also update on startup
    this.updateFromPublicSources();
  }
  
  /**
   * Update blocklist from public threat intelligence sources
   * 
   * CUSTOMIZATION POINT: Add your own threat intelligence feeds here
   * 
   * @private
   */
  private async updateFromPublicSources(): Promise<void> {
    try {
      logger.info('Updating IP blocklist from public sources');
      
      // CUSTOMIZATION POINT: Replace this with actual threat intelligence feeds
      // Example: Fetch from a public blocklist (this is a placeholder URL)
      // In a real implementation, you would use actual threat intelligence feeds
      const response = await axios.get('https://example.com/api/malicious-ips');
      
      if (response.status === 200 && Array.isArray(response.data)) {
        const newIPs = response.data.filter(ip => !this.blocklist.has(ip));
        
        newIPs.forEach(ip => this.blocklist.add(ip));
        this.saveBlocklist();
        
        logger.info(\`Added \${newIPs.length} new IPs to blocklist\`);
      }
    } catch (error) {
      logger.error('Error updating IP blocklist:', error);
    }
  }
}

// Create singleton instance
export const ipBlocklist = new IPBlocklist();
`,
  'src/security/bot-detector.ts': `import { logSecurityEvent } from '../utils/logger';

/**
 * Bot Detector
 * 
 * This class implements various methods to detect bot traffic.
 * It analyzes user agents, headers, and request patterns.
 * 
 * CUSTOMIZATION:
 * - Add your own detection patterns in suspiciousPatterns
 * - Add additional detection methods as needed
 * - Adjust thresholds for detection sensitivity
 */
export class BotDetector {
  /**
   * Patterns to detect in user agents
   * CUSTOMIZATION POINT: Add your own patterns here
   */
  private suspiciousPatterns: RegExp[] = [
    /bot/i,
    /crawl/i,
    /spider/i,
    /scrape/i
  ];
  
  /**
   * Headers that might indicate proxy usage or IP spoofing
   * CUSTOMIZATION POINT: Add additional suspicious headers
   */
  private suspiciousHeaders: string[] = [
    'x-forwarded-for',
    'via',
    'forwarded',
    'client-ip',
    'x-real-ip'
  ];
  
  /**
   * Check if a user agent string is suspicious
   * 
   * @param userAgent - User agent string to check
   * @returns true if suspicious, false otherwise
   */
  isSuspiciousUserAgent(userAgent: string): boolean {
    if (!userAgent || userAgent.length < 10) {
      return true;
    }
    
    return this.suspiciousPatterns.some(pattern => pattern.test(userAgent));
  }
  
  /**
   * Check if request headers indicate potential bot behavior
   * 
   * @param headers - Request headers
   * @returns true if headers are abnormal, false otherwise
   */
  hasAbnormalHeaders(headers: Record<string, string | string[] | undefined>): boolean {
    // Check for proxy headers that might indicate IP spoofing
    const proxyHeaderCount = this.suspiciousHeaders.filter(
      header => headers[header] !== undefined
    ).length;
    
    return proxyHeaderCount >= 3;
  }
  
  /**
   * Check for abnormal request behavior
   * 
   * @param req - Express request object
   * @returns true if behavior is abnormal, false otherwise
   */
  hasAbnormalBehavior(req: any): boolean {
    // Check for unusual request patterns
    const hasReferer = !!req.headers.referer;
    const hasAcceptHeader = !!req.headers.accept;
    const hasAcceptLanguage = !!req.headers['accept-language'];
    const hasAcceptEncoding = !!req.headers['accept-encoding'];
    
    // Most legitimate browsers will have these headers
    if (!hasReferer && !hasAcceptLanguage && !hasAcceptEncoding) {
      return true;
    }
    
    return false;
  }
  
  /**
   * Detect if a request is from a bot
   * 
   * @param req - Express request object
   * @returns Object with isBot flag and reason
   */
  detectBot(req: any): { isBot: boolean; reason: string | null } {
    const userAgent = req.headers['user-agent'] || '';
    
    // Check user agent
    if (this.isSuspiciousUserAgent(userAgent)) {
      logSecurityEvent('BOT_DETECTED', req.ip, { 
        reason: 'Suspicious user agent',
        userAgent
      });
      return { isBot: true, reason: 'Suspicious user agent' };
    }
    
    // Check headers
    if (this.hasAbnormalHeaders(req.headers)) {
      logSecurityEvent('BOT_DETECTED', req.ip, { 
        reason: 'Abnormal headers',
        headers: req.headers
      });
      return { isBot: true, reason: 'Abnormal headers' };
    }
    
    // Check behavior
    if (this.hasAbnormalBehavior(req)) {
      logSecurityEvent('BOT_DETECTED', req.ip, { 
        reason: 'Abnormal behavior'
      });
      return { isBot: true, reason: 'Abnormal behavior' };
    }
    
    return { isBot: false, reason: null };
  }
}

// Create singleton instance
export const botDetector = new BotDetector();
`,
  'src/middleware/security.ts': `import { Request, Response, NextFunction } from 'express';
import { rateLimiter } from '../security/rate-limiter';
import { ipBlocklist } from '../security/ip-blocklist';
import { botDetector } from '../security/bot-detector';
import { logSecurityEvent } from '../utils/logger';
import { config } from '../config';

/**
 * Security Middleware
 * 
 * This middleware applies security checks to all incoming requests.
 * It checks IP blocklists, rate limiting, and bot detection.
 * 
 * CUSTOMIZATION:
 * - Add additional security checks as needed
 * - Customize response messages and status codes
 * - Add whitelisting for trusted IPs or services
 */
export const securityMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip;
  
  // 1. Check IP blocklist
  if (ipBlocklist.isBlocked(ip)) {
    logSecurityEvent('BLOCKED_REQUEST', ip, { 
      reason: 'IP in blocklist',
      path: req.path
    });
    return res.status(403).send('Access Denied');
  }
  
  // 2. Check rate limiting
  if (rateLimiter.isRateLimited(ip)) {
    return res.status(429).send('Too Many Requests');
  }
  
  // 3. Check for bot behavior
  const botCheck = botDetector.detectBot(req);
  if (botCheck.isBot) {
    logSecurityEvent('BOT_BLOCKED', ip, { 
      reason: botCheck.reason,
      path: req.path,
      userAgent: req.headers['user-agent']
    });
    return res.status(403).send('Access Denied');
  }
  
  next();
};

/**
 * Authentication Middleware for Dashboard
 * 
 * This middleware protects the dashboard and admin API routes.
 * It checks for valid username and password in query parameters.
 * 
 * SECURITY NOTE: In a production environment, you should use a more
 * secure authentication method like sessions or JWT tokens.
 * 
 * CUSTOMIZATION:
 * - Replace with a more secure authentication method
 * - Add rate limiting for authentication attempts
 */
export const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const { username, password } = req.query;
  
  if (
    username === config.dashboard.adminUsername && 
    password === config.dashboard.adminPassword
  ) {
    next();
  } else {
    res.status(401).send('Unauthorized');
  }
};
`,
  'src/routes/api.ts': `import express from 'express';
import { rateLimiter } from '../security/rate-limiter';
import { ipBlocklist } from '../security/ip-blocklist';
import { authMiddleware } from '../middleware/security';
import { logger } from '../utils/logger';
import { config } from '../config';

/**
 * API Routes
 * 
 * This module defines API endpoints for the security system.
 * All admin routes are protected by authentication.
 * 
 * CUSTOMIZATION:
 * - Add additional API endpoints as needed
 * - Implement more advanced IP management features
 * - Add endpoints for configuration management
 */
const router = express.Router();

// Protected routes - require authentication
router.use('/admin', authMiddleware);

/**
 * Get security statistics
 * 
 * Endpoint: GET /api/admin/stats
 * Access: Requires authentication
 * Returns: JSON object with security statistics
 * 
 * Example URL: http://localhost:3000/api/admin/stats?username=admin&password=changeme
 */
router.get('/admin/stats', (req, res) => {
  const stats = {
    rateLimiter: rateLimiter.getStats(),
    blockedIPs: {
      fromRateLimiter: rateLimiter.getBlockedIPs(),
      fromBlocklist: ipBlocklist.getBlockedIPs()
    }
  };
  
  res.json(stats);
});

/**
 * Add IP to blocklist
 * 
 * Endpoint: POST /api/admin/block-ip
 * Access: Requires authentication
 * Body: { "ip": "192.168.1.1" }
 * Returns: JSON response with success/error message
 * 
 * Example URL: http://localhost:3000/api/admin/block-ip?username=admin&password=changeme
 */
router.post('/admin/block-ip', (req, res) => {
  const { ip } = req.body;
  
  if (!ip) {
    return res.status(400).json({ error: 'IP address is required' });
  }
  
  try {
    ipBlocklist.addIP(ip);
    logger.info(\`Manually added IP \${ip} to blocklist\`);
    res.json({ success: true, message: \`IP \${ip} added to blocklist\` });
  } catch (error) {
    logger.error('Error adding IP to blocklist:', error);
    res.status(500).json({ error: 'Failed to add IP to blocklist' });
  }
});

/**
 * Remove IP from blocklist
 * 
 * Endpoint: POST /api/admin/unblock-ip
 * Access: Requires authentication
 * Body: { "ip": "192.168.1.1" }
 * Returns: JSON response with success/error message
 * 
 * Example URL: http://localhost:3000/api/admin/unblock-ip?username=admin&password=changeme
 */
router.post('/admin/unblock-ip', (req, res) => {
  const { ip } = req.body;
  
  if (!ip) {
    return res.status(400).json({ error: 'IP address is required' });
  }
  
  try {
    ipBlocklist.removeIP(ip);
    logger.info(\`Manually removed IP \${ip} from blocklist\`);
    res.json({ success: true, message: \`IP \${ip} removed from blocklist\` });
  } catch (error) {
    logger.error('Error removing IP from blocklist:', error);
    res.status(500).json({ error: 'Failed to remove IP from blocklist' });
  }
});

export default router;
`,
  'src/routes/dashboard.ts': `import express from 'express';
import path from 'path';
import fs from 'fs';
import { authMiddleware } from '../middleware/security';
import { config } from '../config';

/**
 * Dashboard Routes
 * 
 * This module defines routes for the security dashboard.
 * All dashboard routes are protected by authentication.
 * 
 * CUSTOMIZATION:
 * - Add additional dashboard pages as needed
 * - Implement more advanced visualization features
 * - Add configuration management UI
 */
const router = express.Router();

// Protect all dashboard routes with authentication
router.use(authMiddleware);

/**
 * Dashboard home page
 * 
 * Endpoint: GET /dashboard
 * Access: Requires authentication
 * Renders: dashboard.pug template
 * 
 * Example URL: http://localhost:3000/dashboard?username=admin&password=changeme
 */
router.get('/', (req, res) => {
  res.render('dashboard', {
    title: 'Security Dashboard',
    env: config.server.env
  });
});

/**
 * Security logs viewer
 * 
 * Endpoint: GET /dashboard/logs
 * Access: Requires authentication
 * Renders: logs.pug template
 * 
 * Example URL: http://localhost:3000/dashboard/logs?username=admin&password=changeme
 */
router.get('/logs', (req, res) => {
  const logPath = path.join(config.paths.logs, 'security.log');
  
  try {
    if (fs.existsSync(logPath)) {
      const logs = fs.readFileSync(logPath, 'utf8')
        .split('\\n')
        .filter(line => line.trim())
        .map(line => JSON.parse(line));
      
      res.render('logs', {
        title: 'Security Logs',
        logs: logs.slice(-100).reverse() // Show last 100 logs
      });
    } else {
      res.render('logs', {
        title: 'Security Logs',
        logs: [],
        error: 'No logs found'
      });
    }
  } catch (error) {
    res.render('logs', {
      title: 'Security Logs',
      logs: [],
      error: 'Error reading logs'
    });
  }
});

export default router;
`,
  'src/server.ts': `import express from 'express';
import path from 'path';
import { config } from './config';
import { logger } from './utils/logger';
import { securityMiddleware } from './middleware/security';
import apiRoutes from './routes/api';
import dashboardRoutes from './routes/dashboard';

/**
 * Main Server Application
 * 
 * This is the entry point for the application.
 * It sets up the Express server, middleware, and routes.
 * 
 * CUSTOMIZATION:
 * - Add additional middleware as needed
 * - Configure CORS if needed
 * - Add health check endpoints
 */

// Create Express app
const app = express();

// Configure view engine for dashboard templates
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Apply security middleware to all routes
app.use(securityMiddleware);

// Routes
app.use('/api', apiRoutes);
app.use('/dashboard', dashboardRoutes);

// Home route
app.get('/', (req, res) => {
  res.send('Protected Server - Access Restricted');
});

// Start server
const server = app.listen(config.server.port, () => {
  logger.info(`Server running in ${config.server.env} mode on port ${config.server.port}`);
});

// Handle shutdown gracefully
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

export default server;
`,
  'src/views/dashboard.pug': `doctype html
html(lang="en")
  head
    meta(charset="UTF-8")
    meta(name="viewport", content="width=device-width, initial-scale=1.0")
    title #{title} | Botnet Protection
    link(rel="stylesheet", href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css")
    script(src="https://cdn.jsdelivr.net/npm/chart.js@4.2.1/dist/chart.umd.min.js")
    style.
      body { padding-top: 20px; }
      .card { margin-bottom: 20px; }
  body
    .container
      header.mb-4
        h1 #{title}
        p.text-muted Environment: #{env}
        p.text-info 
          strong How to use: 
          | This dashboard shows security statistics and allows you to manage blocked IPs.
      
      .row
        .col-md-6
          .card
            .card-header
              h5.card-title Rate Limiting Stats
            .card-body
              canvas#rateLimitChart
        
        .col-md-6
          .card
            .card-header
              h5.card-title Blocked IPs
            .card-body
              #blockedIPs
                p Loading...
      
      .row.mt-4
        .col-12
          .card
            .card-header
              h5.card-title Actions
            .card-body
              .row
                .col-md-6
                  h6 Block IP
                  form#blockIpForm
                    .mb-3
                      input.form-control(type="text", name="ip", placeholder="Enter IP address")
                    button.btn.btn-danger(type="submit") Block IP
                
                .col-md-6
                  h6 View Logs
                  a.btn.btn-primary(href="/dashboard/logs?username=#{process.env.ADMIN_USERNAME}&password=#{process.env.ADMIN_PASSWORD}") View Security Logs
    
    script.
      // Fetch stats and update UI
      async function fetchStats() {
        try {
          // Note: In production, you should use a more secure authentication method
          const response = await fetch('/api/admin/stats?username=#{process.env.ADMIN_USERNAME}&password=#{process.env.ADMIN_PASSWORD}');
          const data = await response.json();
          
          // Update blocked IPs list
          const blockedIPsElement = document.getElementById('blockedIPs');
          const allBlockedIPs = [
            ...data.blockedIPs.fromRateLimiter,
            ...data.blockedIPs.fromBlocklist
          ];
          
          if (allBlockedIPs.length === 0) {
            blockedIPsElement.innerHTML = '<p>No IPs currently blocked</p>';
          } else {
            blockedIPsElement.innerHTML = '<ul class="list-group">' + 
              allBlockedIPs.map(ip => \`<li class="list-group-item">\${ip}</li>\`).join('') +
              '</ul>';
          }
          
          // Update chart
          const ctx = document.getElementById('rateLimitChart').getContext('2d');
          new Chart(ctx, {
            type: 'pie',
            data: {
              labels: ['Tracked IPs', 'Blocked IPs'],
              datasets: [{
                data: [
                  data.rateLimiter.totalTracked - data.rateLimiter.currentlyBlocked,
                  data.rateLimiter.currentlyBlocked
                ],
                backgroundColor: ['#36a2eb', '#ff6384']
              }]
            }
          });
        } catch (error) {
          console.error('Error fetching stats:', error);
        }
      }
      
      // Handle block IP form
      document.getElementById('blockIpForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const ip = e.target.elements.ip.value;
        
        if (!ip) return;
        
        try {
          const response = await fetch('/api/admin/block-ip?username=#{process.env.ADMIN_USERNAME}&password=#{process.env.ADMIN_PASSWORD}', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip })
          });
          
          const result = await response.json();
          alert(result.message || 'IP blocked successfully');
          e.target.reset();
          fetchStats();
        } catch (error) {
          console.error('Error blocking IP:', error);
          alert('Failed to block IP');
        }
      });
      
      // Initial load
      fetchStats();
      
      // Refresh every 30 seconds
      setInterval(fetchStats, 30000);
`,
  'src/views/logs.pug': `doctype html
html(lang="en")
  head
    meta(charset="UTF-8")
    meta(name="viewport", content="width=device-width, initial-scale=1.0")
    title #{title} | Botnet Protection
    link(rel="stylesheet", href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css")
    style.
      body { padding-top: 20px; }
      .log-entry { margin-bottom: 10px; border-bottom: 1px solid #eee; padding-bottom: 10px; }
      .log-timestamp { color: #666; font-size: 0.9em; }
      .log-event-type { font-weight: bold; }
      .log-ip { font-family: monospace; }
  body
    .container
      header.mb-4
        h1 #{title}
        a.btn.btn-secondary(href="/dashboard?username=#{process.env.ADMIN_USERNAME}&password=#{process.env.ADMIN_PASSWORD}") Back to Dashboard
      
      if error
        .alert.alert-warning #{error}
      
      if logs && logs.length > 0
        .card
          .card-header
            h5.card-title Recent Security Events
          .card-body
            each log in logs
              .log-entry
                .log-timestamp #{new Date(log.timestamp).toLocaleString()}
                .log-event-type #{log.eventType}
                .log-ip IP: #{log.ip}
                if log.reason
                  .log-reason Reason: #{log.reason}
                if log.userAgent
                  .log-user-agent User Agent: #{log.userAgent}
      else
        .alert.alert-info No security logs found
`,
  'src/public/styles.css': `/* Main styles */
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.6;
  color: #333;
  background-color: #f8f9fa;
  padding: 20px;
}

.container {
  max-width: 1200px;
  margin: 0 auto;
}

/* Dashboard styles */
.stats-card {
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  padding: 20px;
  margin-bottom: 20px;
}

.stats-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 15px;
  color: #2c3e50;
}

.stats-value {
  font-size: 32px;
  font-weight: 700;
  color: #3498db;
}

.stats-label {
  font-size: 14px;
  color: #7f8c8d;
}

/* Table styles */
.data-table {
  width: 100%;
  border-collapse: collapse;
}

.data-table th,
.data-table td {
  padding: 12px 15px;
  text-align: left;
  border-bottom: 1px solid #e1e1e1;
}

.data-table th {
  background-color: #f2f2f2;
  font-weight: 600;
}

.data-table tbody tr:hover {
  background-color: #f5f5f5;
}

/* Button styles */
.btn {
  display: inline-block;
  padding: 8px 16px;
  background-color: #3498db;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  text-decoration: none;
  font-size: 14px;
  transition: background-color 0.3s;
}

.btn:hover {
  background-color: #2980b9;
}

.btn-danger {
  background-color: #e74c3c;
}

.btn-danger:hover {
  background-color: #c0392b;
}

/* Form styles */
.form-group {
  margin-bottom: 15px;
}

.form-control {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
}

.form-control:focus {
  border-color: #3498db;
  outline: none;
  box-shadow: 0 0 5px rgba(52, 152, 219, 0.5);
}

/* Alert styles */
.alert {
  padding: 15px;
  margin-bottom: 20px;
  border: 1px solid transparent;
  border-radius: 4px;
}

.alert-success {
  color: #155724;
  background-color: #d4edda;
  border-color: #c3e6cb;
}

.alert-danger {
  color: #721c24;
  background-color: #f8d7da;
  border-color: #f5c6cb;
}

.alert-warning {
  color: #856404;
  background-color: #fff3cd;
  border-color: #ffeeba;
}

/* Responsive adjustments */
@media (max-width: 768px) {
  .stats-value {
    font-size: 24px;
  }
  
  .data-table th,
  .data-table td {
    padding: 8px 10px;
  }
}
`,
  'README.md': `# Enhanced Botnet Protection System

A comprehensive security system for protecting web applications from botnet attacks.

![Security Dashboard](https://via.placeholder.com/800x400?text=Security+Dashboard)

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Recommended Settings](#recommended-settings)
- [Usage](#usage)
  - [Starting the Server](#starting-the-server)
  - [Accessing the Dashboard](#accessing-the-dashboard)
  - [Managing Security](#managing-security)
- [Security Recommendations](#security-recommendations)
- [Troubleshooting](#troubleshooting)
- [Advanced Configuration](#advanced-configuration)
- [License](#license)

## Features

- **Advanced Rate Limiting**: Automatically detect and block IPs that exceed request thresholds
- **Bot Detection**: Identify malicious bots using behavioral analysis and pattern recognition
- **IP Blocklist Integration**: Maintain and update lists of known malicious IPs
- **Security Dashboard**: Real-time monitoring of security events and traffic patterns
- **Comprehensive Logging**: Detailed logs of all security events for analysis
- **API Access**: Programmatically manage security settings and view statistics

## Installation

1. Clone the repository:
   \`\`\`bash
   git clone https://github.com/yourusername/enhanced-botnet-protection.git
   cd enhanced-botnet-protection
   \`\`\`

2. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`

3. Set up environment variables:
   \`\`\`bash
   cp .env.example .env
   \`\`\`

4. Edit the \`.env\` file with your preferred settings (see [Configuration](#configuration))

5. Build the project:
   \`\`\`bash
   npm run build
   \`\`\`

6. Start the server:
   \`\`\`bash
   npm start
   \`\`\`

## Configuration

### Environment Variables

The system uses the following environment variables for configuration:

| Variable | Description | Default |
|----------|-------------|---------|
| \`PORT\` | The port the server runs on | \`3000\` |
| \`RATE_LIMIT_THRESHOLD\` | Maximum requests allowed per time window | \`100\` |
| \`RATE_LIMIT_WINDOW_MS\` | Time window for rate limiting (milliseconds) | \`60000\` (1 minute) |
| \`IP_BLOCKLIST_UPDATE_INTERVAL\` | How often to update IP blocklists (milliseconds) | \`86400000\` (24 hours) |
| \`ADMIN_USERNAME\` | Username for dashboard access | \`admin\` |
| \`ADMIN_PASSWORD\` | Password for dashboard access | \`changeme\` |

### Recommended Settings

#### Production Environment

For production environments with public-facing applications:

\`\`\`
PORT=3000
RATE_LIMIT_THRESHOLD=50
RATE_LIMIT_WINDOW_MS=30000
IP_BLOCKLIST_UPDATE_INTERVAL=43200000
ADMIN_USERNAME=[strong-username]
ADMIN_PASSWORD=[strong-password]
\`\`\`

This configuration:
- Limits IPs to 50 requests per 30 seconds (more restrictive)
- Updates IP blocklists every 12 hours
- Uses strong credentials for dashboard access

#### Development Environment

For local development and testing:

\`\`\`
PORT=3000
RATE_LIMIT_THRESHOLD=200
RATE_LIMIT_WINDOW_MS=60000
IP_BLOCKLIST_UPDATE_INTERVAL=86400000
ADMIN_USERNAME=admin
ADMIN_PASSWORD=[your-password]
\`\`\`

#### High-Traffic Applications

For applications with legitimate high traffic:

\`\`\`
PORT=3000
RATE_LIMIT_THRESHOLD=300
RATE_LIMIT_WINDOW_MS=30000
IP_BLOCKLIST_UPDATE_INTERVAL=43200000
ADMIN_USERNAME=[strong-username]
ADMIN_PASSWORD=[strong-password]
\`\`\`

## Usage

### Starting the Server

After configuration, start the server:

\`\`\`bash
npm start
\`\`\`

For development with automatic restarts:

\`\`\`bash
npm run dev
\`\`\`

### Accessing the Dashboard

1. Navigate to \`http://localhost:3000/dashboard?username=admin&password=changeme\` (replace with your configured port and credentials)
2. The dashboard URL includes authentication parameters in the query string:
   \`\`\`
   http://localhost:3000/dashboard?username=YOUR_USERNAME&password=YOUR_PASSWORD
   \`\`\`
3. Replace \`YOUR_USERNAME\` and \`YOUR_PASSWORD\` with the values you set in your .env file
4. IMPORTANT: For production use, implement a more secure authentication method

### Managing Security

#### Dashboard Features

The security dashboard provides:

- **Real-time Statistics**: View current rate limiting and blocking statistics
- **Blocked IPs**: See a list of currently blocked IP addresses
- **Security Logs**: Access detailed logs of security events
- **Manual Controls**: Block or unblock specific IP addresses

#### Blocking an IP

To manually block an IP address:

1. Navigate to the dashboard
2. Find the "Block IP" section
3. Enter the IP address
4. Click "Block IP"

#### Viewing Security Logs

To view security event logs:

1. Navigate to the dashboard
2. Click "View Security Logs"
3. Browse the chronological list of security events

## Security Recommendations

For optimal protection against botnet attacks:

1. **Use a Reverse Proxy**: Place Nginx or another reverse proxy in front of your application
   \`\`\`
   [Internet] → [Nginx] → [Botnet Protection] → [Your Application]
   \`\`\`

2. **Regular Log Analysis**: Review security logs weekly to identify attack patterns

3. **Update Blocklists**: Regularly update your IP blocklists with known malicious IPs

4. **Adjust Thresholds**: Monitor false positives and adjust rate limiting thresholds accordingly

5. **Strong Authentication**: Use complex credentials for dashboard access

6. **Network-Level Protection**: Combine with network-level DDoS protection for comprehensive security

## Troubleshooting

### Common Issues

#### Too Many Legitimate Users Blocked

If legitimate users are being blocked:

1. Increase \`RATE_LIMIT_THRESHOLD\`
2. Increase \`RATE_LIMIT_WINDOW_MS\`
3. Implement IP whitelisting for trusted sources

#### Dashboard Access Issues

If you can't access the dashboard:

1. Verify your environment variables are correctly set
2. Check server logs for authentication errors
3. Ensure the server is running on the expected port
4. Make sure to include username and password in the URL query parameters

#### High CPU Usage

If the system is consuming excessive resources:

1. Increase \`IP_BLOCKLIST_UPDATE_INTERVAL\` to reduce update frequency
2. Consider running the protection system on a separate server
3. Implement caching for frequently accessed resources

## Advanced Configuration

### Custom Bot Detection Rules

You can add custom bot detection rules by modifying \`src/security/bot-detector.ts\`:

\`\`\`typescript
// Add custom patterns to detect specific bots
private suspiciousPatterns: RegExp[] = [
  /bot/i,
  /crawl/i,
  /spider/i,
  /scrape/i,
  /your-custom-pattern/i
];
\`\`\`

### Integrating with Nginx

Example Nginx configuration to work with the protection system:

\`\`\`nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
\`\`\`

### Adding Email Alerts

To receive email alerts for security events, add the following to \`src/utils/logger.ts\`:

\`\`\`typescript
import nodemailer from 'nodemailer';

// Configure email transport
const transporter = nodemailer.createTransport({
  host: 'smtp.example.com',
  port: 587,
  secure: false,
  auth: {
    user: 'your-email@example.com',
    pass: 'your-password'
  }
});

// Send email alert for critical security events
export const sendSecurityAlert = async (eventType: string, details: any) => {
  await transporter.sendMail({
    from: 'security@yourdomain.com',
    to: 'admin@yourdomain.com',
    subject: \`Security Alert: \${eventType}\`,
    text: JSON.stringify(details, null, 2)
  });
};
\`\`\`

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Disclaimer**: This system is designed for educational purposes to demonstrate security concepts. Use responsibly and legally.
`
};

async function generateProject() {
  try {
    // Create project directory
    console.log(`Creating project directory: ${projectName}`);
    await fs.mkdir(projectName, { recursive: true });
    
    // Create src directory and subdirectories
    console.log('Creating directory structure');
    await fs.mkdir(path.join(projectName, 'src'), { recursive: true });
    await fs.mkdir(path.join(projectName, 'src/utils'), { recursive: true });
    await fs.mkdir(path.join(projectName, 'src/security'), { recursive: true });
    await fs.mkdir(path.join(projectName, 'src/middleware'), { recursive: true });
    await fs.mkdir(path.join(projectName, 'src/routes'), { recursive: true });
    await fs.mkdir(path.join(projectName, 'src/views'), { recursive: true });
    await fs.mkdir(path.join(projectName, 'src/public'), { recursive: true });
    
    // Create logs and data directories
    await fs.mkdir(path.join(projectName, 'logs'), { recursive: true });
    await fs.mkdir(path.join(projectName, 'data'), { recursive: true });
    
    // Create all files
    for (const [filePath, content] of Object.entries(projectStructure)) {
      const fullPath = path.join(projectName, filePath);
      console.log(`Creating file: ${fullPath}`);
      
      // Ensure directory exists
      const dir = path.dirname(fullPath);
      await fs.mkdir(dir, { recursive: true });
      
      // Write file
      await fs.writeFile(fullPath, content);
    }
    
    console.log('\nEnhanced botnet protection project created successfully!');
    console.log('\n=== HOW TO USE THE PROJECT ===');
    console.log(`1. cd ${projectName}`);
    console.log('2. npm install');
    console.log('3. cp .env.example .env');
    console.log('4. Edit .env with your settings (especially change the default admin password!)');
    console.log('5. npm run build');
    console.log('6. npm start');
    
    console.log('\n=== ACCESSING THE DASHBOARD ===');
    console.log('Access the dashboard at: http://localhost:3000/dashboard?username=admin&password=changeme');
    console.log('(Replace admin and changeme with your actual credentials from .env)');
    console.log('\nIMPORTANT: The authentication method used is basic and for demonstration purposes.');
    console.log('For production use, implement a more secure authentication method.');
    
    return true;
  } catch (error) {
    console.error('Error generating project:', error);
    return false;
  }
}

// Execute the function
await generateProject();