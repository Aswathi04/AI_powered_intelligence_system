# import serial
# import logging

# class GSMAlert:
#     def __init__(self, port='/dev/ttyUSB0', baudrate=9600):
#         self.port = port
#         self.baudrate = baudrate
#         self.ser = None
#         try:
#             self.ser = serial.Serial(port, baudrate, timeout=1)
#             logging.info(f"GSM module connected on {port}")
#         except Exception as e:
#             logging.warning(f"GSM module not connected: {e}")

#     def test_connection(self):
#         if not self.ser:
#             logging.warning("GSM module not available")
#             return False
#         try:
#             self.ser.write(b'AT\r\n')
#             response = self.ser.read(100).decode()
#             if 'OK' in response:
#                 logging.info("GSM module OK")
#                 return True
#             else:
#                 logging.warning("GSM module not responding OK")
#                 return False
#         except Exception as e:
#             logging.warning(f"Error testing GSM: {e}")
#             return False

#     def send_sms(self, phone_number, message):
#         if not self.ser:
#             logging.warning("GSM module not available, cannot send SMS")
#             return False
#         try:
#             # Set SMS mode
#             self.ser.write(b'AT+CMGF=1\r\n')
#             self.ser.read(100)
#             # Set recipient
#             self.ser.write(f'AT+CMGS="{phone_number}"\r\n'.encode())
#             self.ser.read(100)
#             # Send message
#             self.ser.write(f'{message}\x1A'.encode())
#             response = self.ser.read(100).decode()
#             if 'OK' in response:
#                 logging.info(f"SMS sent to {phone_number}")
#                 return True
#             else:
#                 logging.warning("Failed to send SMS")
#                 return False
#         except Exception as e:
#             logging.warning(f"Error sending SMS: {e}")
#             return False


"""
alerts/gsm_alert.py

GSM SMS alert module for Sentinel AI.
Sends SMS via a SIM800/SIM900 GSM module connected over serial.

If no hardware is connected (or the port is wrong), the module
degrades gracefully — it logs the alert to console instead of
crashing the entire dashboard.

Hardware setup:
  Windows : port = 'COM3'  (check Device Manager)
  Linux   : port = '/dev/ttyUSB0'  or  '/dev/ttyAMA0' (Raspberry Pi UART)
  Mac     : port = '/dev/tty.usbserial-XXXX'
"""

import time
import logging

logger = logging.getLogger(__name__)


class GSMAlert:
    def __init__(self, port: str = 'COM3', baudrate: int = 9600, timeout: int = 3):
        """
        Initialise the GSM serial connection.
        Fails silently if hardware is not present — the dashboard will
        still run, but SMS alerts will be logged to console instead.

        Args:
            port    : Serial port the GSM module is connected to.
            baudrate: Baud rate — SIM800L default is 9600.
            timeout : Serial read timeout in seconds.
        """
        self._port = port
        self._baudrate = baudrate
        self._timeout = timeout
        self._serial = None
        self._available = False

        self._connect()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_sms(self, number: str, message: str) -> bool:
        """
        Send an SMS to `number` with body `message`.

        Args:
            number : E.164 format recommended, e.g. '+919876543210'
            message: Plain text, max 160 chars for single SMS.

        Returns:
            True if sent successfully, False otherwise.
        """
        # Truncate to standard SMS length
        message = message[:160]

        if not self._available:
            # Graceful fallback — print to console so alerts aren't silently lost
            logger.warning(
                f"[GSM UNAVAILABLE] SMS to {number}: {message}")
            print(f"[GSM ALERT] → {number}: {message}")
            return False

        try:
            # Set SMS text mode
            self._send_at("AT+CMGF=1", delay=0.5)
            # Set recipient
            self._send_at(f'AT+CMGS="{number}"', delay=0.5)
            # Send message body + Ctrl+Z to submit
            self._serial.write((message + "\x1a").encode())
            time.sleep(3)  # Wait for network acknowledgement
            response = self._serial.read(self._serial.in_waiting).decode(errors='ignore')
            if "+CMGS" in response:
                logger.info(f"SMS sent to {number}")
                return True
            else:
                logger.error(f"SMS failed. Module response: {response}")
                return False

        except Exception as e:
            logger.error(f"SMS send error: {e}")
            return False

    def is_available(self) -> bool:
        """Returns True if the GSM module is connected and responding."""
        return self._available

    def close(self):
        """Release the serial port."""
        if self._serial and self._serial.is_open:
            self._serial.close()
            self._available = False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _connect(self):
        """
        Attempt to open the serial port and verify the GSM module
        responds to the AT handshake command.
        """
        try:
            import serial  # pyserial — only imported if hardware path is taken
            self._serial = serial.Serial(
                port=self._port,
                baudrate=self._baudrate,
                timeout=self._timeout
            )
            time.sleep(1)  # Let the module wake up

            # Handshake — a healthy module replies "OK"
            self._send_at("AT", delay=0.5)
            response = self._serial.read(self._serial.in_waiting).decode(errors='ignore')

            if "OK" in response:
                self._available = True
                logger.info(f"GSM module connected on {self._port}")
                print(f"[GSM] ✓ Module ready on {self._port}")
            else:
                logger.warning(
                    f"GSM module on {self._port} did not respond to AT. "
                    f"SMS alerts disabled.")
                print(f"[GSM] ⚠ No response on {self._port} — SMS disabled")

        except ImportError:
            logger.warning(
                "pyserial not installed. Run: pip install pyserial  "
                "SMS alerts disabled.")
            print("[GSM] ⚠ pyserial not installed — SMS disabled")

        except Exception as e:
            # Port not found, permission denied, hardware absent, etc.
            logger.warning(f"GSM init failed ({e}) — SMS alerts disabled.")
            print(f"[GSM] ⚠ Could not open {self._port} — SMS disabled")

    def _send_at(self, command: str, delay: float = 0.3):
        """Write an AT command to the serial port."""
        if self._serial and self._serial.is_open:
            self._serial.write((command + "\r\n").encode())
            time.sleep(delay)