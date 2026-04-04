"""
twilio_alert.py

Twilio-based SMS alerting for Sentinel AI incidents.
"""

import logging
from datetime import datetime
from twilio.rest import Client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TwilioAlert:
    """Send SMS alerts via Twilio for detected incidents."""
    
    def __init__(self, account_sid, auth_token, from_number):
        """
        Initialize Twilio alert handler.
        
        Args:
            account_sid (str): Twilio account SID
            auth_token (str): Twilio authentication token
            from_number (str): Twilio phone number to send from
        """
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number
    
    def send_sms(self, to_number, message):
        """
        Send an SMS message via Twilio.
        
        Args:
            to_number (str): Recipient phone number
            message (str): Message body
            
        Returns:
            bool: True if successful, False if error occurred
        """
        # Validate to_number
        if not to_number or not isinstance(to_number, str) or not to_number.strip():
            logger.warning("Invalid to_number: empty or invalid value")
            return False
        
        try:
            client = Client(self.account_sid, self.auth_token)
            client.messages.create(
                body=message,
                from_=self.from_number,
                to=to_number
            )
            logger.info(f"✓ SMS sent to {to_number}")
            return True
            
        except Exception as e:
            logger.error(f"✗ Failed to send SMS to {to_number}: {str(e)}")
            return False
    
    def send_alert(self, to_numbers, alert_type, incident_id, threat_score, location):
        """
        Send a formatted alert message to multiple numbers.
        
        Args:
            to_numbers (list): List of recipient phone numbers
            alert_type (str): Type of detection (e.g., "PROXIMITY", "ENCIRCLEMENT")
            incident_id (str): Unique incident identifier
            threat_score (int): Threat score 0-100
            location (str): Location/camera name
            
        Returns:
            int: Number of successfully sent messages
        """
        # Handle empty to_numbers list
        if not to_numbers or len(to_numbers) == 0:
            logger.warning("No recipients provided for alert")
            return 0
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        message = (
            f"🚨 SENTINEL AI ALERT\n"
            f"Type: {alert_type}\n"
            f"Score: {threat_score}/100\n"
            f"Incident: {incident_id}\n"
            f"Time: {timestamp}\n"
            f"Location: {location}"
        )
        
        sent_count = 0
        for to_number in to_numbers:
            if self.send_sms(to_number, message):
                sent_count += 1
        
        logger.info(f"Alert sent to {sent_count}/{len(to_numbers)} recipients")
        return sent_count
