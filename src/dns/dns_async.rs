use crate::{dns::dns_cache::DnsCache, CancellationToken, Error, LteLink, UdpSocket};
use core::{cell::RefCell, convert::TryInto};
use embassy_sync::{blocking_mutex::raw::ThreadModeRawMutex, mutex::Mutex};
use embassy_time::Duration;
use no_std_net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

const DNS_SERVERS: [[u8; 4]; 8] = [
    [8, 8, 8, 8],
    [8, 8, 4, 4],
    [1, 1, 1, 1],
    [1, 0, 0, 1],
    [9, 9, 9, 9],
    [149, 112, 112, 112],
    [76, 76, 2, 0],
    [76, 76, 10, 0],
];
const DNS_SERVER_PORT: u16 = 53;
const BUFFER_SIZE: usize = 512;
const SOCKET_TIMEOUT_SECS: u64 = 10;

// The DNS cache singleton
static DNS_CACHE: Mutex<ThreadModeRawMutex, RefCell<DnsCache>> =
    Mutex::new(RefCell::new(DnsCache::new()));

#[repr(u16)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(clippy::upper_case_acronyms)]
enum RecordType {
    A = 1,
    AAAA = 28,
}

#[derive(Debug)]
struct DNSHeader {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DNSHeader {
    fn new(id: u16) -> Self {
        DNSHeader {
            id,
            flags: 0x0100, // Standard query
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    fn write(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        if buffer.len() < 12 {
            return Err(Error::DnsHeaderBufferOverflow);
        }
        let mut pos = 0;
        buffer[pos..pos + 2].copy_from_slice(&self.id.to_be_bytes());
        pos += 2;
        buffer[pos..pos + 2].copy_from_slice(&self.flags.to_be_bytes());
        pos += 2;
        buffer[pos..pos + 2].copy_from_slice(&self.qdcount.to_be_bytes());
        pos += 2;
        buffer[pos..pos + 2].copy_from_slice(&self.ancount.to_be_bytes());
        pos += 2;
        buffer[pos..pos + 2].copy_from_slice(&self.nscount.to_be_bytes());
        pos += 2;
        buffer[pos..pos + 2].copy_from_slice(&self.arcount.to_be_bytes());
        pos += 2;
        Ok(pos)
    }
}

#[derive(Debug)]
struct DNSQuestion<'a> {
    qname: &'a str,
    qtype: u16,
    qclass: u16,
}

impl<'a> DNSQuestion<'a> {
    fn write(&self, buffer: &mut [u8], mut pos: usize) -> Result<usize, Error> {
        // Encode the domain name into the QNAME field
        for label in self.qname.split('.') {
            let len = label.len();
            if len > 63 || pos + 1 + len >= buffer.len() {
                // Labels must be 63 characters or less
                return Err(Error::DnsQuestionBufferOverflow);
            }
            buffer[pos] = len as u8;
            pos += 1;
            buffer[pos..pos + len].copy_from_slice(label.as_bytes());
            pos += len;
        }
        if pos >= buffer.len() {
            return Err(Error::DnsQuestionBufferOverflow);
        }
        buffer[pos] = 0; // Terminate QNAME with a zero-length label
        pos += 1;

        // Check buffer capacity before writing
        if pos + 4 > buffer.len() {
            return Err(Error::DnsQuestionBufferOverflow);
        }

        // QTYPE
        buffer[pos..pos + 2].copy_from_slice(&self.qtype.to_be_bytes());
        pos += 2;

        // QCLASS (IN for Internet)
        buffer[pos..pos + 2].copy_from_slice(&self.qclass.to_be_bytes());
        pos += 2;

        Ok(pos)
    }
}

pub async fn get_host_by_name(hostname: &str) -> Result<IpAddr, Error> {
    get_host_by_name_with_cancellation(hostname, &Default::default()).await
}

pub async fn get_host_by_name_with_cancellation(
    hostname: &str,
    token: &CancellationToken,
) -> Result<IpAddr, Error> {
    #[cfg(feature = "defmt")]
    defmt::debug!("Resolving dns hostname async for \"{}\"", hostname);

    // If we can parse the hostname as an IP address, then we can save a whole lot of trouble
    if let Ok(ip) = hostname.parse() {
        return Ok(ip);
    }

    // The modem only deals with ascii
    if !hostname.is_ascii() {
        return Err(Error::HostnameNotAscii);
    }

    token.bind_to_current_task().await;

    // Try to get the records from the cache
    let result = {
        let cache = DNS_CACHE.lock().await;
        let result = cache.borrow().get(hostname);
        result
    };
    if let Some(cached_record) = result {
        #[cfg(feature = "defmt")]
        defmt::debug!("DNS cache hit");

        return Ok(cached_record);
    }

    let link = LteLink::new().await?;

    let socket = embassy_time::with_timeout(
        Duration::from_secs(SOCKET_TIMEOUT_SECS),
        UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(0, 0, 0, 0),
            DNS_SERVER_PORT,
        ))),
    )
    .await
    .map_err(|_| Error::DnsSocketTimeout)?
    .map_err(|_| Error::DnsSocketError)?;

    #[cfg(feature = "defmt")]
    defmt::trace!("DNS UDP socket connected");

    let mut response_buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
    let mut query_buffer = [0u8; BUFFER_SIZE];
    let mut addr = None::<IpAddr>;

    for record_type in [RecordType::A, RecordType::AAAA] {
        // Build the DNS query
        let transaction_id = embassy_time::Instant::now().as_micros() as u16;
        let query_size = build_dns_query(&mut query_buffer, hostname, record_type, transaction_id)?;

        #[cfg(feature = "defmt")]
        defmt::trace!("DNS query: {}", &query_buffer[..query_size]);

        for dns_server in DNS_SERVERS {
            if let Ok(size) = send_and_receive_udp(
                &query_buffer[..query_size],
                &socket,
                &dns_server,
                &mut response_buffer,
            )
            .await
            {
                if let Ok(result) =
                    process_dns_response(&response_buffer[..size], transaction_id).await
                {
                    #[cfg(feature = "defmt")]
                    defmt::trace!(
                        "DNS query type {:?} succeeded for host: {} with hostname {}",
                        record_type,
                        dns_server,
                        hostname
                    );
                    addr = Some(result);
                    break;
                };
            } else {
                #[cfg(feature = "defmt")]
                defmt::trace!(
                    "DNS query {:?} failed for host: {}",
                    record_type,
                    dns_server
                );
            }
        }

        if addr.is_some() {
            break;
        }
    }

    // end connection
    socket
        .deactivate()
        .await
        .map_err(|_| Error::DnsSocketError)?;

    link.deactivate().await?;

    addr.ok_or(Error::AddressNotFound)
}

async fn send_and_receive_udp(
    query: &[u8],
    socket: &UdpSocket,
    dns_server: &[u8; 4],
    buffer: &mut [u8],
) -> Result<usize, Error> {
    // send the request
    embassy_time::with_timeout(
        Duration::from_secs(5),
        socket.send_to(
            query,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(*dns_server), 53)),
        ),
    )
    .await
    .map_err(|_| Error::DnsSocketError)
    .and_then(|i| i.map_err(|_| Error::DnsSocketError))?;

    #[cfg(feature = "defmt")]
    defmt::trace!("DNS request sent to {}", dns_server);

    // receive the result
    let (response, _) = embassy_time::with_timeout(
        Duration::from_secs(SOCKET_TIMEOUT_SECS),
        socket.receive_from(buffer),
    )
    .await
    .map_err(|_| Error::DnsSocketError)
    .and_then(|i| i.map_err(|_| Error::DnsSocketError))?;

    #[cfg(feature = "defmt")]
    defmt::trace!("DNS query result received: {:?}", response);

    Ok(response.len())
}

fn build_dns_query(
    buffer: &mut [u8],
    domain_name: &str,
    record_type: RecordType,
    transaction_id: u16,
) -> Result<usize, Error> {
    let header = DNSHeader::new(transaction_id);
    let mut pos = header.write(buffer)?;

    let question = DNSQuestion {
        qname: domain_name,
        qtype: record_type as u16,
        qclass: 1, // IN (Internet)
    };
    pos = question.write(buffer, pos)?;

    Ok(pos)
}

async fn process_dns_response(response: &[u8], transaction_id: u16) -> Result<IpAddr, Error> {
    let mut pos = 0;
    let response_len = response.len();

    // Ensure the response is long enough for the header
    if response_len < 12 {
        return Err(Error::DnsParseFailed);
    }

    // Parse Header
    let id = read_u16(response, &mut pos)?;
    if id != transaction_id {
        return Err(Error::DnsParseFailed);
    }

    // Parse Header
    let flags = read_u16(response, &mut pos)?;

    // Check QR bit
    if flags & 0x8000 == 0 {
        // QR bit not set; this is a query, not a response
        return Err(Error::DnsParseFailed);
    }

    // Check OPCODE (bits 11-14 should be 0 for a standard query)
    if flags & 0x7800 != 0 {
        return Err(Error::DnsParseFailed);
    }

    let qdcount = read_u16(response, &mut pos)?;
    let ancount = read_u16(response, &mut pos)?;
    let _nscount = read_u16(response, &mut pos)?;
    let _arcount = read_u16(response, &mut pos)?;

    // Verify response code in flags
    let rcode = flags & 0x000F;
    if rcode != 0 {
        // Non-zero RCODE indicates an error
        return Err(Error::DnsParseFailed);
    }

    // Skip Question Section
    for _ in 0..qdcount {
        parse_name(response, &mut pos)?; // Parse and ignore the question name
                                         // Skip QTYPE and QCLASS
        pos = pos.checked_add(4).ok_or(Error::DnsParseFailed)?;
        if pos > response_len {
            return Err(Error::DnsParseFailed);
        }
    }

    // Parse Answer Section
    for _ in 0..ancount {
        let (hostname_bytes, hostname_len) = parse_name(response, &mut pos)?; // Parse the answer name
        let hostname = &hostname_bytes[..hostname_len];

        let rtype = read_u16(response, &mut pos)?;
        let _rclass = read_u16(response, &mut pos)?;
        let ttl = read_u32(response, &mut pos)?;
        let rdlength = read_u16(response, &mut pos)?;

        if pos + rdlength as usize > response_len {
            return Err(Error::DnsParseFailed);
        }

        match rtype {
            1 if rdlength == 4 => {
                let ip: [u8; 4] = response[pos..pos + 4].try_into().unwrap();
                let addr = IpAddr::V4(Ipv4Addr::from(ip));
                DNS_CACHE
                    .lock()
                    .await
                    .borrow_mut()
                    .insert(&hostname, &addr, ttl)?;
                return Ok(addr);
            }
            28 if rdlength == 16 => {
                let ip: [u8; 16] = response[pos..pos + 16].try_into().unwrap();
                let addr = IpAddr::V6(Ipv6Addr::from(ip));
                DNS_CACHE
                    .lock()
                    .await
                    .borrow_mut()
                    .insert(&hostname, &addr, ttl)?;
                return Ok(addr);
            }
            _ => {
                // Skip unsupported record types
                pos += rdlength as usize;
                continue;
            }
        };
    }
    Err(Error::DnsParseFailed)
}

// Helper function to parse a domain name from the buffer, handling compression
fn parse_name(buffer: &[u8], pos: &mut usize) -> Result<([u8; BUFFER_SIZE], usize), Error> {
    let buffer_len = buffer.len();
    let mut hostname = [0u8; BUFFER_SIZE];
    let mut hostname_pos = 0;

    let mut current_pos = *pos;
    let mut jumped = false;
    let mut max_jumps = 10; // Prevent infinite loops

    loop {
        if max_jumps == 0 {
            // Too many jumps, possible loop
            return Err(Error::DnsParseFailed);
        }

        if current_pos >= buffer_len {
            return Err(Error::DnsParseFailed);
        }

        let len = buffer[current_pos];

        if len & 0xC0 == 0xC0 {
            // Compression pointer
            if current_pos + 1 >= buffer_len {
                return Err(Error::DnsParseFailed);
            }
            let offset = (((len & 0x3F) as usize) << 8) | (buffer[current_pos + 1] as usize);
            if offset >= buffer_len {
                return Err(Error::DnsParseFailed);
            }
            if !jumped {
                // Save the position to update the caller's position later
                *pos = current_pos + 2;
            }
            current_pos = offset;
            jumped = true;
        } else if len == 0 {
            // Null label
            if !jumped {
                *pos = current_pos + 1;
            }
            break;
        } else {
            current_pos += 1;
            if current_pos + len as usize > buffer_len
                || hostname_pos + len as usize + 1 > hostname.len()
            {
                return Err(Error::DnsParseFailed);
            }

            // Copy the label
            hostname[hostname_pos..hostname_pos + len as usize]
                .copy_from_slice(&buffer[current_pos..current_pos + len as usize]);
            hostname_pos += len as usize;
            hostname[hostname_pos] = b'.';
            hostname_pos += 1;

            current_pos += len as usize;
        }

        max_jumps -= 1;
    }

    if hostname_pos == 0 {
        return Err(Error::DnsParseFailed);
    }

    // Remove the trailing dot
    hostname_pos -= 1;

    Ok((hostname, hostname_pos))
}

// Helper function to read a u16 from the buffer
fn read_u16(buffer: &[u8], pos: &mut usize) -> Result<u16, Error> {
    if *pos + 2 > buffer.len() {
        return Err(Error::DnsParseFailed);
    }
    let val = u16::from_be_bytes([buffer[*pos], buffer[*pos + 1]]);
    *pos += 2;
    Ok(val)
}

// Helper function to read a u32 from the buffer
fn read_u32(buffer: &[u8], pos: &mut usize) -> Result<u32, Error> {
    if *pos + 4 > buffer.len() {
        return Err(Error::DnsParseFailed);
    }
    let val = u32::from_be_bytes([
        buffer[*pos],
        buffer[*pos + 1],
        buffer[*pos + 2],
        buffer[*pos + 3],
    ]);
    *pos += 4;
    Ok(val)
}
