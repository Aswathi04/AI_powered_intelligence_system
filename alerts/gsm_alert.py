import serial
import logging

class GSMAlert:
    def __init__(self, port='/dev/ttyUSB0', baudrate=9600):
        self.port = port
        self.baudrate = baudrate
        self.ser = None
        try:
            self.ser = serial.Serial(port, baudrate, timeout=1)
            logging.info(f"GSM module connected on {port}")
        except Exception as e:
            logging.warning(f"GSM module not connected: {e}")

    def test_connection(self):
        if not self.ser:
            logging.warning("GSM module not available")
            return False
        try:
            self.ser.write(b'AT\r\n')
            response = self.ser.read(100).decode()
            if 'OK' in response:
                logging.info("GSM module OK")
                return True
            else:
                logging.warning("GSM module not responding OK")
                return False
        except Exception as e:
            logging.warning(f"Error testing GSM: {e}")
            return False

    def send_sms(self, phone_number, message):
        if not self.ser:
            logging.warning("GSM module not available, cannot send SMS")
            return False
        try:
            # Set SMS mode
            self.ser.write(b'AT+CMGF=1\r\n')
            self.ser.read(100)
            # Set recipient
            self.ser.write(f'AT+CMGS="{phone_number}"\r\n'.encode())
            self.ser.read(100)
            # Send message
            self.ser.write(f'{message}\x1A'.encode())
            response = self.ser.read(100).decode()
            if 'OK' in response:
                logging.info(f"SMS sent to {phone_number}")
                return True
            else:
                logging.warning("Failed to send SMS")
                return False
        except Exception as e:
            logging.warning(f"Error sending SMS: {e}")
            return False