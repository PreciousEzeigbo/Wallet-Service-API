import httpx
import hashlib
import hmac
from typing import Optional
from app.config import get_settings

settings = get_settings()


class PaystackClient:
    """Client for Paystack API"""
    
    BASE_URL = "https://api.paystack.co"
    
    def __init__(self):
        self.secret_key = settings.paystack_secret_key
        self.headers = {
            "Authorization": f"Bearer {self.secret_key}",
            "Content-Type": "application/json"
        }
    
    async def initialize_transaction(self, email: str, amount: int, reference: str) -> dict:
        """
        Initialize a Paystack transaction
        
        Args:
            email: User's email
            amount: Amount in kobo (smallest currency unit)
            reference: Unique transaction reference
        
        Returns:
            dict with authorization_url and reference
        """
        url = f"{self.BASE_URL}/transaction/initialize"
        data = {
            "email": email,
            "amount": amount,
            "reference": reference,
            "callback_url": f"{settings.app_url}/wallet/paystack/callback"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=data, headers=self.headers)
            response.raise_for_status()
            result = response.json()
            
            if not result.get("status"):
                raise Exception(result.get("message", "Transaction initialization failed"))
            
            return result["data"]
    
    async def verify_transaction(self, reference: str) -> dict:
        """
        Verify a transaction with Paystack
        
        Args:
            reference: Transaction reference
        
        Returns:
            dict with transaction details
        """
        url = f"{self.BASE_URL}/transaction/verify/{reference}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers)
            response.raise_for_status()
            result = response.json()
            
            if not result.get("status"):
                raise Exception(result.get("message", "Transaction verification failed"))
            
            return result["data"]
    
    @staticmethod
    def verify_webhook_signature(payload: bytes, signature: str) -> bool:
        """
        Verify Paystack webhook signature
        
        Args:
            payload: Request body bytes
            signature: x-paystack-signature header value
        
        Returns:
            bool indicating if signature is valid
        """
        computed_signature = hmac.new(
            settings.paystack_secret_key.encode('utf-8'),
            payload,
            hashlib.sha512
        ).hexdigest()
        
        return hmac.compare_digest(computed_signature, signature)
