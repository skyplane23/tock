use core::cell::Cell;
use kernel::common::cells::OptionalCell;
use kernel::common::registers::{register_bitfields, ReadWrite};
use kernel::common::StaticRef;
use kernel::ClockInterface;
use kernel::ReturnCode;
use kernel::{debug, hil};

// use crate::dma1;
// use crate::dma1::Dma1Peripheral;
use crate::rcc;

/// Universal synchronous asynchronous receiver transmitter
#[repr(C)]
struct UsartRegisters {
    /// Control register 1
    cr1: ReadWrite<u32, CR1::Register>,
    /// Control register 2
    cr2: ReadWrite<u32, CR2::Register>,
    /// Control register 3
    cr3: ReadWrite<u32, CR3::Register>,
    /// Baud rate register
    brr: ReadWrite<u32, BRR::Register>,
    /// Guard time and prescaler register
    gtpr: ReadWrite<u32, GTPR::Register>,
    /// Receiver timeout register
    rtor: ReadWrite<u32, RTOR::Register>,
    /// Request register
    rqr: ReadWrite<u32, RTOR::Register>,
    /// Interrupt and status register
    isr: ReadWrite<u32, ISR::Register>,
    /// Interrupt flag clear register
    icr: ReadWrite<u32, ISR::Register>,
    /// Receive data register
    rdr: ReadWrite<u32>,
    /// Transmit data register
    tdr: ReadWrite<u32>,
}

register_bitfields![u32,
    CR1 [
        /// Word length
        M1 OFFSET(28) NUMBITS(1) [],
        /// End of Block interrupt enable
        EOBIE OFFSET(15) NUMBITS(1) [],
        /// Receiver timeout interrupt enable
        RTOIE OFFSET(26) NUMBITS(1) [],
        /// Driver Enable assertion time
        DEAT OFFSET(21) NUMBITS(5) [],
        /// Driver Enable de-assertion time
        DEDT OFFSET(16) NUMBITS(5) [],
        /// Oversampling mode
        OVER8 OFFSET(15) NUMBITS(1) [],
        /// Character match interrupt enable
        CMIE OFFSET(14) NUMBITS(1) [],
        /// Mute mode enable
        MME OFFSET(13) NUMBITS(1) [],
        /// Word length
        M0 OFFSET(12) NUMBITS(1) [],
        /// Wakeup method
        WAKE OFFSET(11) NUMBITS(1) [],
        /// Parity control enable
        PCE OFFSET(10) NUMBITS(1) [],
        /// Parity selection
        PS OFFSET(9) NUMBITS(1) [],
        /// PE interrupt enable
        PEIE OFFSET(8) NUMBITS(1) [],
        /// TXE interrupt enable
        TXEIE OFFSET(7) NUMBITS(1) [],
        /// Transmission complete interrupt enable
        TCIE OFFSET(6) NUMBITS(1) [],
        /// RXNE interrupt enable
        RXNEIE OFFSET(5) NUMBITS(1) [],
        /// IDLE interrupt enable
        IDLEIE OFFSET(4) NUMBITS(1) [],
        /// Transmitter enable
        TE OFFSET(3) NUMBITS(1) [],
        /// Receiver enable
        RE OFFSET(2) NUMBITS(1) [],
        /// USART enable in Stop mode
        UESM OFFSET(1) NUMBITS(1) [],
        /// USART enable
        UE OFFSET(0) NUMBITS(1) []
    ],
    CR2 [
        /// Address of the USART node
        ADD1 OFFSET(28) NUMBITS(1) [],
        /// Address of the USART node
        ADD0 OFFSET(24) NUMBITS(4) [],
        /// Receiver timeout enable
        RTOEN OFFSET(23) NUMBITS(1) [],
        /// Auto baud rate mode
        ABRMOD OFFSET(21) NUMBITS(2) [],
        /// Auto baud rate enable
        ABREN OFFSET(20) NUMBITS(1) [],
        /// Most significant bit first
        MSBFIRST OFFSET(19) NUMBITS(1) [],
        /// Binary data inversion
        DATAINV OFFSET(18) NUMBITS(1) [],
        /// TX pin active level inversion
        TXINV OFFSET(17) NUMBITS(1) [],
        /// RX pin active level inversion
        RXINV OFFSET(16) NUMBITS(1) [],
        /// Swap TX/RX pins
        SWAP OFFSET(15) NUMBITS(1) [],
        /// LIN mode enable
        LINEN OFFSET(14) NUMBITS(1) [],
        /// STOP bits
        STOP OFFSET(12) NUMBITS(2) [],
        /// Clock enable
        CLKEN OFFSET(11) NUMBITS(1) [],
        /// Clock polarity
        CPOL OFFSET(10) NUMBITS(1) [],
        /// Clock phase
        CPHA OFFSET(9) NUMBITS(1) [],
        /// Last bit clock pulse
        LBCL OFFSET(8) NUMBITS(1) [],
        /// LIN break detection interrupt enable
        LBDIE OFFSET(6) NUMBITS(1) [],
        /// lin break detection length
        LBDL OFFSET(5) NUMBITS(1) [],
        /// 7-bit Address Detection/4-bit Address Detection
        ADDM7 OFFSET(4) NUMBITS(1) []
    ],
    CR3 [
        /// Wakeup from Stop mode interrupt enable
        WUFIE OFFSET(22) NUMBITS(1) [],
        /// Wakeup from Stop mode interrupt flag selection
        WUS OFFSET(20) NUMBITS(2) [],
        /// Smartcard auto-retry count
        SCARCNT OFFSET(17) NUMBITS(2) [],
        /// Driver enable polarity selection
        DEP OFFSET(15) NUMBITS(1) [],
        /// Driver enable mode
        DEM OFFSET(14) NUMBITS(1) [],
        /// DMA Disable on Reception Error
        DDRE OFFSET(13) NUMBITS(1) [],
        /// Overrun Disable
        OVRDIS OFFSET(12) NUMBITS(1) [],
        /// One sample bit method enable
        ONEBIT OFFSET(11) NUMBITS(1) [],
        /// CTS interrupt enable
        CTSIE OFFSET(10) NUMBITS(1) [],
        /// CTS enable
        CTSE OFFSET(9) NUMBITS(1) [],
        /// RTS enable
        RTSE OFFSET(8) NUMBITS(1) [],
        /// DMA enable transmitter
        DMAT OFFSET(7) NUMBITS(1) [],
        /// DMA enable receiver
        DMAR OFFSET(6) NUMBITS(1) [],
        /// Smartcard mode enable
        SCEN OFFSET(5) NUMBITS(1) [],
        /// Smartcard NACK enable
        NACK OFFSET(4) NUMBITS(1) [],
        /// Half-duplex selection
        HDSEL OFFSET(3) NUMBITS(1) [],
        /// IrDA low-power
        IRLP OFFSET(2) NUMBITS(1) [],
        /// IrDA mode enable
        IREN OFFSET(1) NUMBITS(1) [],
        /// Error interrupt enable
        EIE OFFSET(0) NUMBITS(1) []
    ],
    BRR [
        /// mantissa of USARTDIV
        DIV_Mantissa OFFSET(4) NUMBITS(12) [],
        /// fraction of USARTDIV
        DIV_Fraction OFFSET(0) NUMBITS(4) []
    ],
    GTPR [
        /// Guard time value
        GT OFFSET(8) NUMBITS(8) [],
        /// Prescaler value
        PSC OFFSET(0) NUMBITS(8) []
    ],
    RTOR [
        /// Block Length
        BLEN OFFSET(24) NUMBITS(8) [],
        /// Receiver timeout value
        RTO OFFSET(0) NUMBITS(24) []
    ],
    RQR [
        /// Transmit data flush request
        TXFRQ OFFSET(0) NUMBITS(1) [],
        /// Receive data flush request
        RXFRQ OFFSET(3) NUMBITS(1) [],
        /// Mute mode request
        MMRQ OFFSET(2) NUMBITS(1) [],
        /// Send break request
        SBKRQ OFFSET(1) NUMBITS(1) [],
        /// Auto baud rate request
        ABRRQ OFFSET(0) NUMBITS(1) []
    ],
    ISR [
        /// Receive enable acknowledge flag
        REACK OFFSET(22) NUMBITS(1) [],
        /// Transmit enable acknowledge flag
        TEACK OFFSET(21) NUMBITS(1) [],
        /// Wakeup from Stop mode flag
        WUF OFFSET(20) NUMBITS(1) [],
        /// Receiver wakeup from Mute mode
        RWU OFFSET(19) NUMBITS(1) [],
        /// Send break flag
        SBKF OFFSET(18) NUMBITS(1) [],
        /// Character match flag
        CMF OFFSET(17) NUMBITS(1) [],
        /// Busy flag
        BUSY OFFSET(16) NUMBITS(1) [],
        /// Auto baud rate flag
        ABRF OFFSET(15) NUMBITS(1) [],
        /// Auto baud rate error
        ABRE OFFSET(14) NUMBITS(1) [],
        /// End of block flag
        EOBF OFFSET(12) NUMBITS(1) [],
        /// Receiver timeout
        RTOF OFFSET(11) NUMBITS(1) [],
        /// CTS flag
        CTS OFFSET(10) NUMBITS(1) [],
        /// CTS interrupt flag
        CTSIF OFFSET(9) NUMBITS(1) [],
        /// LIN break detection flag
        LBDF OFFSET(8) NUMBITS(1) [],
        /// Transmit data register empty
        TXE OFFSET(7) NUMBITS(1) [],
        /// Transmission complete
        TC OFFSET(6) NUMBITS(1) [],
        /// Read data register not empty
        RXNE OFFSET(5) NUMBITS(1) [],
        /// IDLE line detected
        IDLE OFFSET(4) NUMBITS(1) [],
        /// Overrun error
        ORE OFFSET(3) NUMBITS(1) [],
        /// Noise detected flag
        NF OFFSET(2) NUMBITS(1) [],
        /// Framing error
        FE OFFSET(1) NUMBITS(1) [],
        /// Parity error
        PE OFFSET(0) NUMBITS(1) []
    ],
    ICR [
        /// Wakeup from Stop mode clear flag
        WUCF OFFSET(20) NUMBITS(1) [],
        /// Character match clear flag
        CMCF OFFSET(17) NUMBITS(1) [],
        /// End of block clear flag
        EOBCF OFFSET(12) NUMBITS(1) [],
        /// Receiver timeout clear flag
        RTOCF OFFSET(11) NUMBITS(1) [],
        /// CTS clear flag
        CTSCF OFFSET(9) NUMBITS(1) [],
        /// LIN break detection clear flag
        LBDCF OFFSET(8) NUMBITS(1) [],
        /// Transmission complete clear flag
        TCCF OFFSET(6) NUMBITS(1) [],
        /// Idle line detected clear flag
        IDLECF OFFSET(4) NUMBITS(1) [],
        /// Overrun error clear flag
        ORECF OFFSET(3) NUMBITS(1) [],
        /// Noise detected clear flag
        NCF OFFSET(2) NUMBITS(1) [],
        /// Framing error clear flag
        FECF OFFSET(1) NUMBITS(1) [],
        /// Parity error clear flag
        PECF OFFSET(0) NUMBITS(1) []
    ]
];

const USART1_BASE: StaticRef<UsartRegisters> =
    unsafe { StaticRef::new(0x40013800 as *const UsartRegisters) };
const USART2_BASE: StaticRef<UsartRegisters> =
    unsafe { StaticRef::new(0x40004400 as *const UsartRegisters) };
const USART3_BASE: StaticRef<UsartRegisters> =
    unsafe { StaticRef::new(0x40004800 as *const UsartRegisters) };

pub struct Usart<'a> {
    registers: StaticRef<UsartRegisters>,
    clock: UsartClock,

    tx_client: OptionalCell<&'a dyn hil::uart::TransmitClient>,
    rx_client: OptionalCell<&'a dyn hil::uart::ReceiveClient>,

    tx_len: Cell<usize>,
    rx_len: Cell<usize>,
}

pub static mut USART1: Usart = Usart::new(
    USART1_BASE,
    UsartClock(rcc::PeripheralClock::APB2(rcc::PCLK2::USART1)),
);

pub static mut USART2: Usart = Usart::new(
    USART2_BASE,
    UsartClock(rcc::PeripheralClock::APB1(rcc::PCLK1::USART2)),
);

pub static mut USART3: Usart = Usart::new(
    USART3_BASE,
    UsartClock(rcc::PeripheralClock::APB1(rcc::PCLK1::USART3)),
);

impl Usart<'a> {
    const fn new(base_addr: StaticRef<UsartRegisters>, clock: UsartClock) -> Usart<'a> {
        Usart {
            registers: base_addr,
            clock: clock,

            tx_client: OptionalCell::empty(),
            rx_client: OptionalCell::empty(),

            tx_len: Cell::new(0),
            rx_len: Cell::new(0),
        }
    }

    pub fn is_enabled_clock(&self) -> bool {
        self.clock.is_enabled()
    }

    pub fn enable_clock(&self) {
        self.clock.enable();
    }

    pub fn disable_clock(&self) {
        self.clock.disable();
    }

    // for use by panic in io.rs
    pub fn send_byte(&self, byte: u8) {
        // loop till TXE (Transmit data register empty) becomes 1
        while !self.registers.isr.is_set(ISR::TXE) {}
        self.registers.tdr.set(byte.into());
    }

    fn enable_transmit_complete_interrupt(&self) {
        self.registers.cr1.modify(CR1::TCIE::SET);
    }

    fn disable_transmit_complete_interrupt(&self) {
        self.registers.cr1.modify(CR1::TCIE::CLEAR);
    }

    fn clear_transmit_complete(&self) {
        self.registers.isr.modify(ISR::TC::CLEAR);
    }

    pub fn handle_interrupt(&self) {
        self.clear_transmit_complete();
        self.disable_transmit_complete_interrupt();

        debug!("transmit");

        self.enable_transmit_complete_interrupt();
    }
}

impl hil::uart::Transmit<'a> for Usart<'a> {
    fn set_transmit_client(&self, client: &'a dyn hil::uart::TransmitClient) {
        self.tx_client.set(client);
    }

    // TODO
    fn transmit_buffer(
        &self,
        tx_data: &'static mut [u8],
        _tx_len: usize,
    ) -> (ReturnCode, Option<&'static mut [u8]>) {
        for byte in tx_data {
            self.send_byte(*byte);
        }
        (ReturnCode::SUCCESS, None)
    }

    fn transmit_word(&self, _word: u32) -> ReturnCode {
        ReturnCode::FAIL
    }

    fn transmit_abort(&self) -> ReturnCode {
        ReturnCode::SUCCESS
    }
}

impl hil::uart::Configure for Usart<'a> {
    fn configure(&self, params: hil::uart::Parameters) -> ReturnCode {
        if params.baud_rate != 115200
            || params.stop_bits != hil::uart::StopBits::One
            || params.parity != hil::uart::Parity::None
            || params.hw_flow_control != false
            || params.width != hil::uart::Width::Eight
        {
            panic!(
                "Currently we only support uart setting of 115200bps 8N1, no hardware flow control"
            );
        }

        // Configure the word length - 0: 1 Start bit, 8 Data bits, n Stop bits
        self.registers.cr1.modify(CR1::M0::CLEAR);
        self.registers.cr1.modify(CR1::M1::CLEAR);

        // Set the stop bit length - 00: 1 Stop bits
        self.registers.cr2.modify(CR2::STOP.val(0b00 as u32));

        // Set no parity
        self.registers.cr1.modify(CR1::PCE::CLEAR);

        // Set the baud rate. By default OVER8 is 0 (oversampling by 16) and
        // PCLK1 is at 8Mhz. The desired baud rate is 115.2KBps. So according
        // to Table 159 of reference manual, the value for BRR is 69.444 (0x45)
        // DIV_Fraction = 0x5
        // DIV_Mantissa = 0x4
        self.registers.brr.modify(BRR::DIV_Fraction.val(0x5 as u32));
        self.registers.brr.modify(BRR::DIV_Mantissa.val(0x4 as u32));

        // Enable transmit block
        self.registers.cr1.modify(CR1::TE::SET);

        // Enable receive block
        self.registers.cr1.modify(CR1::RE::SET);

        // Enable USART
        self.registers.cr1.modify(CR1::UE::SET);

        ReturnCode::SUCCESS
    }
}

impl hil::uart::Receive<'a> for Usart<'a> {
    fn set_receive_client(&self, client: &'a dyn hil::uart::ReceiveClient) {
        self.rx_client.set(client);
    }

    fn receive_buffer(
        &self,
        _rx_buffer: &'static mut [u8],
        _rx_len: usize,
    ) -> (ReturnCode, Option<&'static mut [u8]>) {
        (ReturnCode::FAIL, None)
    }

    fn receive_word(&self) -> ReturnCode {
        ReturnCode::FAIL
    }

    fn receive_abort(&self) -> ReturnCode {
        ReturnCode::EBUSY
    }
}

impl hil::uart::UartData<'a> for Usart<'a> {}
impl hil::uart::Uart<'a> for Usart<'a> {}

struct UsartClock(rcc::PeripheralClock);

impl ClockInterface for UsartClock {
    fn is_enabled(&self) -> bool {
        self.0.is_enabled()
    }

    fn enable(&self) {
        self.0.enable();
    }

    fn disable(&self) {
        self.0.disable();
    }
}
