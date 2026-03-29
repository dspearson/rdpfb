/// Security module for RDP server
///
/// Provides rate limiting and connection tracking
use anyhow::{Result, bail};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Security limits and constants
mod limits {
    use std::time::Duration;

    /// Maximum connections per IP
    pub const MAX_CONNECTIONS_PER_IP: usize = 5;

    /// Connection attempt window (60 seconds)
    pub fn rate_limit_window() -> Duration {
        Duration::from_secs(60)
    }

    /// Maximum connection attempts per window
    pub const MAX_ATTEMPTS_PER_WINDOW: usize = 10;

    /// Session timeout (30 minutes of inactivity)
    pub fn session_timeout() -> Duration {
        Duration::from_secs(30 * 60)
    }
}

/// Connection tracking for rate limiting
#[derive(Debug, Clone)]
struct ConnectionAttempt {
    timestamp: Instant,
    count: usize,
}

/// Rate limiter for DoS protection
#[derive(Clone)]
pub struct RateLimiter {
    attempts: Arc<Mutex<HashMap<IpAddr, ConnectionAttempt>>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new() -> Self {
        RateLimiter {
            attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if connection attempt is allowed
    pub fn check_connection(&self, ip: IpAddr) -> Result<()> {
        let mut attempts = self.attempts.lock().unwrap_or_else(|e| e.into_inner());

        let now = Instant::now();

        // Clean up old entries
        attempts.retain(|_, attempt| {
            now.duration_since(attempt.timestamp) < limits::rate_limit_window()
        });

        // Check current IP
        let attempt = attempts.entry(ip).or_insert(ConnectionAttempt {
            timestamp: now,
            count: 0,
        });

        // Reset if window expired
        if now.duration_since(attempt.timestamp) >= limits::rate_limit_window() {
            attempt.timestamp = now;
            attempt.count = 0;
        }

        // Check limit
        if attempt.count >= limits::MAX_ATTEMPTS_PER_WINDOW {
            bail!(
                "Rate limit exceeded for IP: {} ({} attempts in {} seconds)",
                ip,
                attempt.count,
                limits::rate_limit_window().as_secs()
            );
        }

        attempt.count += 1;
        Ok(())
    }

    /// Record successful connection (resets rate limit)
    pub fn record_success(&self, ip: IpAddr) {
        let mut attempts = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        attempts.remove(&ip);
    }

    /// Get current attempt count for IP
    pub fn get_attempts(&self, ip: IpAddr) -> usize {
        let attempts = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        attempts.get(&ip).map(|a| a.count).unwrap_or(0)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection manager for tracking active connections
#[derive(Clone)]
pub struct ConnectionManager {
    connections: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new() -> Self {
        ConnectionManager {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if new connection is allowed for this IP
    pub fn check_connection_limit(&self, ip: IpAddr) -> Result<()> {
        let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());

        // Clean up stale connections
        for (_ip, times) in connections.iter_mut() {
            times.retain(|t| t.elapsed() < limits::session_timeout());
        }

        // Check limit for this IP
        let conn_times = connections.entry(ip).or_default();

        if conn_times.len() >= limits::MAX_CONNECTIONS_PER_IP {
            bail!(
                "Connection limit exceeded for IP: {} ({} active connections)",
                ip,
                conn_times.len()
            );
        }

        conn_times.push(Instant::now());
        Ok(())
    }

    /// Remove a connection for an IP
    pub fn remove_connection(&self, ip: IpAddr) {
        let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(times) = connections.get_mut(&ip) {
            if !times.is_empty() {
                times.pop();
            }
        }
    }

    /// Get active connection count for IP
    pub fn get_connection_count(&self, ip: IpAddr) -> usize {
        let connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        connections.get(&ip).map(|v| v.len()).unwrap_or(0)
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // First attempts should succeed
        for _ in 0..limits::MAX_ATTEMPTS_PER_WINDOW {
            assert!(limiter.check_connection(ip).is_ok());
        }

        // Next attempt should fail
        assert!(limiter.check_connection(ip).is_err());
    }

    #[test]
    fn test_connection_manager() {
        let manager = ConnectionManager::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should allow up to MAX_CONNECTIONS_PER_IP
        for _ in 0..limits::MAX_CONNECTIONS_PER_IP {
            assert!(manager.check_connection_limit(ip).is_ok());
        }

        // Next connection should fail
        assert!(manager.check_connection_limit(ip).is_err());

        // Removing a connection should allow another
        manager.remove_connection(ip);
        assert!(manager.check_connection_limit(ip).is_ok());
    }

    #[test]
    fn test_record_success_resets_attempts() {
        let limiter = RateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Make several attempts
        for _ in 0..5 {
            limiter.check_connection(ip).unwrap();
        }
        assert_eq!(limiter.get_attempts(ip), 5);

        // Record success should reset
        limiter.record_success(ip);
        assert_eq!(limiter.get_attempts(ip), 0);
    }

    #[test]
    fn test_get_attempts_and_connection_count() {
        let limiter = RateLimiter::new();
        let manager = ConnectionManager::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Initially zero
        assert_eq!(limiter.get_attempts(ip), 0);
        assert_eq!(manager.get_connection_count(ip), 0);

        // After some attempts/connections
        limiter.check_connection(ip).unwrap();
        limiter.check_connection(ip).unwrap();
        assert_eq!(limiter.get_attempts(ip), 2);

        manager.check_connection_limit(ip).unwrap();
        manager.check_connection_limit(ip).unwrap();
        manager.check_connection_limit(ip).unwrap();
        assert_eq!(manager.get_connection_count(ip), 3);
    }

    #[test]
    fn test_different_ips_tracked_independently() {
        let limiter = RateLimiter::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Exhaust ip1
        for _ in 0..limits::MAX_ATTEMPTS_PER_WINDOW {
            limiter.check_connection(ip1).unwrap();
        }
        assert!(limiter.check_connection(ip1).is_err());

        // ip2 should still be allowed
        assert!(limiter.check_connection(ip2).is_ok());
        assert_eq!(limiter.get_attempts(ip2), 1);

        // Connection manager too
        let manager = ConnectionManager::new();
        for _ in 0..limits::MAX_CONNECTIONS_PER_IP {
            manager.check_connection_limit(ip1).unwrap();
        }
        assert!(manager.check_connection_limit(ip1).is_err());
        assert!(manager.check_connection_limit(ip2).is_ok());
    }

    #[test]
    fn test_default_impls() {
        let limiter = RateLimiter::default();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(limiter.check_connection(ip).is_ok());

        let manager = ConnectionManager::default();
        assert!(manager.check_connection_limit(ip).is_ok());
    }
}
