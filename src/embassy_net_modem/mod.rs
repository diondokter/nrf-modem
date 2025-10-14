// Modified from embassy-rs:
// Licence: https://github.com/embassy-rs/embassy/blob/main/LICENSE-APACHE
// Source file: https://github.com/embassy-rs/embassy/blob/a8cb8a7fe1f594b765dee4cfc6ff3065842c7c6e/embassy-net-nrf91/src/lib.rs

use core::cell::RefCell;
use core::mem::MaybeUninit;

use embassy_futures::select::{select, Either};
use embassy_net_driver_channel as ch;
use embassy_time::Timer;

pub mod context;

use crate::socket::Socket;
const MTU: usize = 1500;

/// Network driver.
///
/// This is the type you have to pass to `embassy-net` when creating the network stack.
pub type NetDriver<'a> = ch::Device<'a, MTU>;

/// Create a new nrf-modem embassy-net driver.
pub async fn new<'a>(state: &'a mut State) -> (NetDriver<'a>, Control<'a>, Runner<'a>) {
    let state_inner = &*state
        .inner
        .write(RefCell::new(StateInner { net_socket: None }));

    let control = Control { state: state_inner };

    let (ch_runner, device) = ch::new(&mut state.ch, ch::driver::HardwareAddress::Ip);
    let state_ch = ch_runner.state_runner();
    state_ch.set_link_state(ch::driver::LinkState::Up);

    let runner = Runner {
        ch: ch_runner,
        state: state_inner,
    };

    (device, control, runner)
}

/// Shared state for the driver.
pub struct State {
    ch: ch::State<MTU, 4, 4>,
    inner: MaybeUninit<RefCell<StateInner>>,
}

impl State {
    /// Create a new State.
    pub const fn new() -> Self {
        Self {
            ch: ch::State::new(),
            inner: MaybeUninit::uninit(),
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

struct StateInner {
    net_socket: Option<Socket>,
}

/// Control handle for the driver.
///
/// You can use this object to control the modem at runtime, such as running AT commands.
pub struct Control<'a> {
    state: &'a RefCell<StateInner>,
}

pub(crate) const CAP_SIZE: usize = 256;

impl<'a> Control<'a> {
    /// Open the raw socket used for sending/receiving IP packets.
    async fn open_raw_socket(&self) {
        let socket = Socket::create(
            crate::socket::SocketFamily::Raw,
            crate::socket::SocketType::Raw,
            crate::socket::SocketProtocol::IP,
        )
        .await
        .unwrap();
        self.state.borrow_mut().net_socket = Some(socket);
    }

    async fn close_raw_socket(&self) {
        let sock = self.state.borrow_mut().net_socket.take();
        if let Some(s) = sock {
            s.deactivate().await.unwrap();
        }
    }
    /// Run an AT command.
    ///
    /// The response is written in `resp` and its length returned.
    pub async fn at_command(&self, commad: &[u8]) -> arrayvec::ArrayString<CAP_SIZE> {
        crate::send_at(core::str::from_utf8(commad).unwrap())
            .await
            .unwrap()
    }
}

/// Background runner for the driver.
pub struct Runner<'a> {
    ch: ch::Runner<'a, MTU>,
    state: &'a RefCell<StateInner>,
}

impl<'a> Runner<'a> {
    /// Run the driver operation in the background.
    ///
    /// You must run this in a background task, concurrently with all network operations.
    pub async fn run(mut self) -> ! {
        loop {
            let (_, mut rx_chan, mut tx_chan) = self.ch.borrow_split();
            let net_socket = self.state.borrow_mut().net_socket.take();

            let mut rx_buf = [0; 2048];

            let token: crate::CancellationToken = Default::default();

            if let Some(socket) = net_socket {
                let rx_fut = async {
                    let size = socket
                        .receive_with_cancellation(&mut rx_buf, &token)
                        .await
                        .unwrap();
                    let buf = rx_chan.rx_buf().await;
                    (size, buf)
                };
                let tx_fut = tx_chan.tx_buf();
                match select(rx_fut, tx_fut).await {
                    Either::First((size, buf)) => {
                        if size > 0 {
                            // Process received data
                            buf[..size].copy_from_slice(&rx_buf[..size]);
                            rx_chan.rx_done(size);
                        }
                    }
                    Either::Second(buf) => {
                        let size = buf.len();
                        let mut remaining = size;
                        while remaining > 0 {
                            let size = socket
                                .write_with_cancellation(&buf[size - remaining..], &token)
                                .await
                                .unwrap();
                            remaining -= size;
                        }
                        tx_chan.tx_done();
                    }
                }

                self.state.borrow_mut().net_socket.replace(socket);
            } else {
                Timer::after_millis(100).await
            }
        }
    }
}
