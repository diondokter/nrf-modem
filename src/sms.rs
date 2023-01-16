use crate::{
    error::{Error, ErrorSource},
    send_at, LteLink,
};

use core::fmt::Write;
use core::write;
use heapless::{String, Vec};

// ASCII table for coverting ASCII to GSM 7 bit
// Copied from https://github.com/nrfconnect/sdk-nrf/blob/main/lib/sms/string_conversion.c#L36

const ASCII_TO_7BIT_TABLE: [u8; 256] = [
    /* Standard ASCII, character codes 0-127 */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, /* 0-7:   Control characters */
    0x20, 0x20, 0x0A, 0x20, 0x20, 0x0D, 0x20, 0x20, /* 8-15:  ...LF,..CR...      */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, /* 16-31: Control characters */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x21, 0x22, 0x23, 0x02, 0x25, 0x26,
    0x27, /* 32-39: SP ! " # $ % & ' */
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, /* 40-47: ( ) * + , - . /  */
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 48-55: 0 1 2 3 4 5 6 7  */
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, /* 56-63: 8 9 : ; < = > ?  */
    0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, /* 64-71: @ A B C D E F G  */
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, /* 72-79: H I J K L M N O  */
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, /* 80-87: P Q R S T U V W  */
    0x58, 0x59, 0x5A, 0xBC, 0xAF, 0xBE, 0x94, 0x11, /* 88-95: X Y Z [ \ ] ^ _  */
    0x27, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* 96-103: (` -> ') a b c d e f g */
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, /* 104-111:h i j k l m n o  */
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, /* 112-119: p q r s t u v w  */
    0x78, 0x79, 0x7A, 0xA8, 0xC0, 0xA9, 0xBD, 0x20, /* 120-127: x y z { | } ~ DEL */
    /* Character codes 128-255 (beyond standard ASCII) have different possible
     * interpretations. This table has been done according to ISO-8859-15.
     */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, /* 128-159: Undefined   */
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x40, 0x63, 0x01, 0xE5, 0x03, 0x53,
    0x5F, /* 160-167: ..£, €... */
    0x73, 0x63, 0x20, 0x20, 0x20, 0x2D, 0x20, 0x20, /* 168-175 */
    0x20, 0x20, 0x20, 0x20, 0x5A, 0x75, 0x0A, 0x20, /* 176-183 */
    0x7A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x59, 0x60, /* 184-191 */
    0x41, 0x41, 0x41, 0x41, 0x5B, 0x0E, 0x1C, 0x09, /* 192-199: ..Ä, Å... */
    0x45, 0x1F, 0x45, 0x45, 0x49, 0x49, 0x49, 0x49, /* 200-207 */
    0x44, 0x5D, 0x4F, 0x4F, 0x4F, 0x4F, 0x5C, 0x2A, /* 208-215: ..Ö... */
    0x0B, 0x55, 0x55, 0x55, 0x5E, 0x59, 0x20, 0x1E, /* 216-223 */
    0x7F, 0x61, 0x61, 0x61, 0x7B, 0x0F, 0x1D, 0x63, /* 224-231: ..ä, å... */
    0x04, 0x05, 0x65, 0x65, 0x07, 0x69, 0x69, 0x69, /* 232-239 */
    0x20, 0x7D, 0x08, 0x6F, 0x6F, 0x6F, 0x7C, 0x2F, /* 240-247: ..ö... */
    0x0C, 0x06, 0x75, 0x75, 0x7E, 0x79, 0x20, 0x79, /* 248-255 */
];

// Masks need when encoding ASCII to GSM 7 bit
const STR_7BIT_ESCAPE_IND: u8 = 0x80;
const STR_7BIT_CODE_MASK: u8 = 0x7F;
const STR_7BIT_ESCAPE_CODE: u8 = 0x1B;

/// A struct holding both number and message with can be send as an SMS
pub struct Sms<'a> {
    number: &'a str,
    message: &'a str,
}

impl<'a> Sms<'a> {
    /// Creates a new Sms message
    /// `number` should be in national format, including the country code at start. The + character is not need at start and will be ignored.
    /// Max `message` lenght 160 chars
    pub fn new(number: &'a str, message: &'a str) -> Self {
        Self { number, message }
    }
    // Encode number in the way modem expect it
    // Reimplement from https://github.com/nrfconnect/sdk-nrf/blob/main/lib/sms/sms_submit.c#L46
    fn encode_number(number: &str) -> Result<String<15>, Error> {
        let mut encoded_number = String::from(number.trim_start_matches("+"));

        if encoded_number.len() % 2 != 0 {
            encoded_number
                .push('F')
                .map_err(|_| Error::BufferTooSmall(None))?;
        }

        if number.is_ascii() {
            // Since we are checking if the number of characters is even before this unsafe
            // and we only allow ASCII chars doing this swap shouldn't have any UB
            unsafe {
                for c in encoded_number.as_bytes_mut().array_chunks_mut::<2>() {
                    c.swap(0, 1);
                }
            }

            Ok(encoded_number)
        } else {
            Err(Error::SmsNumberNotAscii)
        }
    }
    // Convert a ASCII string to GSM 7bit
    // Reimplement from https://github.com/nrfconnect/sdk-nrf/blob/main/lib/sms/string_conversion.c#L162
    fn ascii_to_gsm7bit<const N: usize>(text: &str) -> Result<String<N>, Error> {
        let mut encoded_message = String::new();

        for c in text.chars() {
            if c.is_ascii() {
                let char_7bit = ASCII_TO_7BIT_TABLE[c as usize];
                if char_7bit & STR_7BIT_ESCAPE_IND == 0 {
                    encoded_message
                        .push(char_7bit as char)
                        .map_err(|_| Error::BufferTooSmall(None))?;
                } else {
                    encoded_message
                        .push(STR_7BIT_ESCAPE_CODE as char)
                        .map_err(|_| Error::BufferTooSmall(None))?;
                    encoded_message
                        .push((char_7bit & STR_7BIT_CODE_MASK) as char)
                        .map_err(|_| Error::BufferTooSmall(None))?;
                }
            }
        }

        Ok(encoded_message)
    }
    // Pack a GSM 7 bit strings into 7 bites without 1 bit padding
    // Reimplement from https://github.com/nrfconnect/sdk-nrf/blob/main/lib/sms/string_conversion.c#L294
    fn pack_gsm7bit<const N: usize>(text: String<N>) -> Vec<u8, N> {
        let mut src: usize = 0;
        let mut dst: usize = 0;
        let mut shift: usize = 0;
        let len = text.len();
        let mut bytes = text.into_bytes();

        while src < len {
            bytes[dst] = bytes[src] >> shift;
            src += 1;
            if src < len {
                bytes[dst] |= bytes[src] << (7 - shift);
                shift += 1;
                if shift == 7 {
                    shift = 0;
                    src += 1;
                }
            }
            dst += 1;
        }
        bytes.truncate(dst);
        bytes
    }
    /// Sends the craftes message
    /// `N` is need to provide internal buffer size for message and number encoding. Needs to be at least 2 * message.len() + 34
    /// Max ever need value for the buffer should be not more then 354 bytes
    pub async fn send<const N: usize>(self) -> Result<(), Error> {
        let encoded_number = Self::encode_number(self.number)?;

        let encoded_message = Self::pack_gsm7bit(Self::ascii_to_gsm7bit::<N>(self.message)?);

        let size = 2 + /* First header byte and TP-MR fields */
		1 + /* Length of phone number */
		1 + /* Phone number Type-of-Address byte */
		encoded_number.len()/2 +
		2 + /* TP-PID and TP-DCS fields */
		1 + /* TP-UDL field */
		encoded_message.len();

        let mut at_cmgs: String<N> = String::new();
        let mut encoded_number_len = encoded_number.len();
        if self.number.trim_start_matches('+').len() % 2 != 0 {
            encoded_number_len -= 1;
        }
        // Write the at command and begin with encoded number and it's lenght
        write!(
            &mut at_cmgs,
            "AT+CMGS={}\r{:04X}{:04X}91{}",
            size, 0x01, encoded_number_len, encoded_number
        )
        .map_err(|_| Error::BufferTooSmall(None))?;
        // Write the message lenght
        write!(&mut at_cmgs, "00{:04X}", self.message.len())
            .map_err(|_| Error::BufferTooSmall(None))?;
        // Write the GSM 7 bit packaged message as hex string
        for c in &encoded_message {
            write!(&mut at_cmgs, "{:02X}", c).map_err(|_| Error::BufferTooSmall(None))?;
        }
        // End character
        write!(&mut at_cmgs, "\x1A").map_err(|_| Error::BufferTooSmall(None))?;

        // Wait for LteLink to send the message
        let lte_link = LteLink::new().await?;
        lte_link.wait_for_link().await?;

        // Configure the SMS parameters in modem
        // This might need some rework when reciving SMS is add and reporting
        if send_at::<6>("AT+CNMI=3,2,0,1").await?.as_str() != "OK\r\n" {
            return Err(Error::UnexpectedAtResponse);
        }

        // Send the SMS
        lte_link.deactivate().await?;
        if send_at::<6>(&at_cmgs).await?.ends_with("OK\r\n") {
            Ok(())
        } else {
            Err(Error::UnexpectedAtResponse)
        }
    }
}
