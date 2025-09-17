use crate::Error;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{AddrType, DnsQuery};

/// The maximum domain name length
const MAX_DOMAIN_LEN: usize = 256;

// Fixed-size buffer for DNS records
const CACHE_BUFFER_SIZE: usize = 1024;

// Get max data length
const fn max(a: u8, b: u8) -> u8 {
    if a > b {
        a
    } else {
        b
    }
}
const DATA_BUFFER_SIZE: usize = max(IPV4_ADDR_LENGTH, IPV6_ADDR_LENGTH) as usize;

// Data lengths for IPv4 and IPv6
const IPV4_ADDR_LENGTH: u8 = 4;
const IPV6_ADDR_LENGTH: u8 = 16;

// Compile time check for buffer size
const CACHE_HEADER_SIZE: usize = 11; // custom serialization, cannot use mem::size
const _: () = assert!(
    MAX_DOMAIN_LEN + CACHE_HEADER_SIZE + DATA_BUFFER_SIZE < CACHE_BUFFER_SIZE,
    "CACHE_BUFFER must fit at least one entry"
);

/// Represents the DNS cache
pub struct DnsCache {
    head: usize, // Index where new data will be written
    tail: usize, // Index of the oldest data
    cache: [u8; CACHE_BUFFER_SIZE],
}

impl DnsCache {
    /// Creates a new cache instance
    pub const fn new() -> Self {
        Self {
            head: 0,
            tail: 0,
            cache: [0; CACHE_BUFFER_SIZE],
        }
    }

    /// Inserts a new entry into the cache.
    pub fn insert(&mut self, hostname: &[u8], ip: &IpAddr, ttl: u32) -> Result<(), Error> {
        #[cfg(feature = "defmt")]
        match ip {
            IpAddr::V4(ipv4_addr) => defmt::trace!(
                "create dns cache entry with {} -> {} and ttl {}",
                core::str::from_utf8(hostname).unwrap(),
                ipv4_addr.octets(),
                ttl
            ),
            IpAddr::V6(ipv6_addr) => defmt::trace!(
                "create dns cache entry with {} -> {} and ttl {}",
                core::str::from_utf8(hostname).unwrap(),
                ipv6_addr.octets(),
                ttl
            ),
        }

        // Ensure key lengths fit into MAX_DOMAIN_LEN
        if hostname.len() > MAX_DOMAIN_LEN {
            return Err(Error::DomainNameTooLong);
        }

        let is_ipv4: bool;
        let data_length = match ip {
            IpAddr::V4(_) => {
                is_ipv4 = true;
                IPV4_ADDR_LENGTH
            }
            IpAddr::V6(_) => {
                is_ipv4 = false;
                IPV6_ADDR_LENGTH
            }
        };

        let header = CacheEntryHeader {
            data_length,
            ttl,
            timestamp: embassy_time::Instant::now().as_secs() as u32,
            is_ipv4,
            key_length: hostname.len() as u8,
        };

        #[cfg(feature = "defmt")]
        defmt::trace!(
            "space remaining in DNS cache: {} bytes",
            self.space_remaining()
        );

        // Evict old entries if necessary to make space
        while self.space_remaining() < header.size() {
            if !self.evict_oldest_entry()? {
                // Buffer is full and cannot evict more entries
                return Err(Error::DnsCacheOverflow);
            }
        }

        // Write the header
        self.write_bytes(&header.to_bytes())?;

        // Write the key
        self.write_bytes(hostname)?;

        // Write the data
        match ip {
            IpAddr::V4(ipv4_addr) => self.write_bytes(&ipv4_addr.octets())?,
            IpAddr::V6(ipv6_addr) => self.write_bytes(&ipv6_addr.octets())?,
        };

        Ok(())
    }

    /// Retrieves a cache entry matching the given criteria.
    pub fn get(&self, query: DnsQuery<'_>) -> Option<IpAddr> {
        let mut pos = self.tail;
        let mut key_buffer: [u8; MAX_DOMAIN_LEN] = [0; MAX_DOMAIN_LEN];
        let mut data_buffer: [u8; DATA_BUFFER_SIZE] = [0; DATA_BUFFER_SIZE];

        while pos != self.head {
            // Read the header
            let header = self.read_header(pos).ok()?;

            // Check if the entry has expired
            let current_time = embassy_time::Instant::now().as_secs() as u32;
            if current_time - header.timestamp > header.ttl {
                // Entry has expired; move to the next
                pos = (pos + header.size()) % CACHE_BUFFER_SIZE;
                continue;
            }

            // Check if the address type matches
            match query.addr_type() {
                AddrType::Any => (),
                AddrType::V4 => {
                    if !header.is_ipv4 {
                        continue;
                    }
                }
                AddrType::V6 => {
                    if header.is_ipv4 {
                        continue;
                    }
                }
            }

            // Check the key
            let key_start = (pos + CACHE_HEADER_SIZE) % CACHE_BUFFER_SIZE;
            self.read_bytes(
                key_start,
                header.key_length as usize,
                &self.cache,
                &mut key_buffer,
            )
            .ok()?;
            // Compare keys
            if &key_buffer[..header.key_length as usize] == query.hostname().as_bytes() {
                // Key matches; read the data
                let data_start = (key_start + header.key_length as usize) % CACHE_BUFFER_SIZE;
                let result = self.read_bytes(
                    data_start,
                    header.data_length as usize,
                    &self.cache,
                    &mut data_buffer,
                );
                return result
                    .map(|_| match header.is_ipv4 {
                        true => {
                            let mut buf = [0u8; IPV4_ADDR_LENGTH as usize];
                            buf.copy_from_slice(&data_buffer[..IPV4_ADDR_LENGTH as usize]);
                            IpAddr::V4(Ipv4Addr::from(buf))
                        }
                        false => {
                            let mut buf = [0u8; IPV6_ADDR_LENGTH as usize];
                            buf.copy_from_slice(&data_buffer[..IPV6_ADDR_LENGTH as usize]);
                            IpAddr::V6(Ipv6Addr::from(buf))
                        }
                    })
                    .ok();
            }

            // Move to the next entry
            pos = (pos + header.size()) % CACHE_BUFFER_SIZE;
        }

        None
    }

    /// Calculates the remaining space in the buffer
    fn space_remaining(&self) -> usize {
        if self.head >= self.tail {
            CACHE_BUFFER_SIZE - (self.head - self.tail)
        } else {
            self.tail - self.head
        }
    }

    /// Writes bytes to the buffer at the head position
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let bytes_len = bytes.len();
        let end_pos = (self.head + bytes_len) % CACHE_BUFFER_SIZE;

        if self.space_remaining() < bytes_len {
            return Err(Error::DnsCacheOverflow);
        }

        if end_pos >= self.head {
            // No wrap-around
            self.cache[self.head..end_pos].copy_from_slice(bytes);
        } else {
            // Wrap-around occurs
            let first_part_size = CACHE_BUFFER_SIZE - self.head;
            self.cache[self.head..].copy_from_slice(&bytes[..first_part_size]);
            self.cache[..end_pos].copy_from_slice(&bytes[first_part_size..]);
        }

        self.head = end_pos;
        Ok(())
    }

    /// Reads bytes from the buffer starting at the given position
    fn read_bytes(
        &self,
        pos: usize,
        length: usize,
        cache: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        if pos > CACHE_BUFFER_SIZE - 1 {
            return Err(Error::DnsCacheOverflow);
        }

        if length > CACHE_BUFFER_SIZE {
            return Err(Error::DnsCacheOverflow);
        }

        let end_pos = (pos + length) % CACHE_BUFFER_SIZE;

        if length == 0 {
            return Ok(());
        }

        if end_pos > pos {
            // No wrap-around
            if end_pos > CACHE_BUFFER_SIZE {
                return Err(Error::DnsCacheOverflow);
            }
            buffer[..length].copy_from_slice(&cache[pos..end_pos]);
            Ok(())
        } else {
            // Wrap-around occurs
            if pos >= CACHE_BUFFER_SIZE || length > CACHE_BUFFER_SIZE {
                return Err(Error::DnsCacheOverflow);
            }

            let first_part_size = CACHE_BUFFER_SIZE - pos;
            let second_part_size = length - first_part_size;

            // Copy first part
            buffer[..first_part_size].copy_from_slice(&cache[pos..]);

            // Copy second part
            buffer[first_part_size..length].copy_from_slice(&cache[..second_part_size]);

            Ok(())
        }
    }

    /// Reads a header from the buffer at the given position
    fn read_header(&self, pos: usize) -> Result<CacheEntryHeader, Error> {
        if pos > CACHE_BUFFER_SIZE - 1 {
            return Err(Error::DnsCacheOverflow);
        }

        let mut header_bytes = [0u8; CACHE_HEADER_SIZE];

        let end_pos = (pos + CACHE_HEADER_SIZE) % CACHE_BUFFER_SIZE;

        if end_pos > pos {
            // No wrap-around
            header_bytes.copy_from_slice(&self.cache[pos..end_pos]);
        } else {
            // Wrap-around occurs
            let first_part_size = CACHE_BUFFER_SIZE - pos;
            header_bytes[..first_part_size].copy_from_slice(&self.cache[pos..]);
            header_bytes[first_part_size..].copy_from_slice(&self.cache[..end_pos]);
        }

        Ok(CacheEntryHeader::from_bytes(&header_bytes))
    }

    /// Evicts the oldest entry from the buffer
    /// Returns `true` if an entry was evicted, `false` if the buffer is empty
    fn evict_oldest_entry(&mut self) -> Result<bool, Error> {
        if self.head == self.tail {
            // Buffer is empty
            return Ok(false);
        }

        // Read the header at the tail
        let header = self.read_header(self.tail)?;

        // Move the tail forward
        self.tail = (self.tail + header.size()) % CACHE_BUFFER_SIZE;

        Ok(true)
    }
}

/// Represents the cache entry header
#[derive(Debug, Clone, Copy)]
struct CacheEntryHeader {
    data_length: u8, // Length of the data in bytes
    ttl: u32,        // Time to live in seconds
    timestamp: u32,  // Time when the entry was added
    is_ipv4: bool,   // IPv4 or IPv6
    key_length: u8,  // Length of the domain name key
}

impl CacheEntryHeader {
    /// Serializes the header into bytes
    fn to_bytes(self) -> [u8; CACHE_HEADER_SIZE] {
        let mut bytes = [0u8; CACHE_HEADER_SIZE];
        bytes[0] = self.data_length;
        bytes[1..5].copy_from_slice(&self.ttl.to_be_bytes());
        bytes[5..9].copy_from_slice(&self.timestamp.to_be_bytes());
        bytes[9] = self.is_ipv4 as u8;
        bytes[10] = self.key_length;
        bytes
    }

    /// Deserializes the header from bytes
    fn from_bytes(bytes: &[u8]) -> Self {
        let data_length = bytes[0];
        let ttl = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let timestamp = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        let is_ipv4 = bytes[9] == 1;
        let key_length = bytes[10];
        CacheEntryHeader {
            data_length,
            ttl,
            timestamp,
            is_ipv4,
            key_length,
        }
    }

    /// Calculate the size of the header
    fn size(&self) -> usize {
        CACHE_HEADER_SIZE + self.key_length as usize + self.data_length as usize
    }
}
