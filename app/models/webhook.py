from pydantic import BaseModel
from typing import List, Optional

class CardInfo(BaseModel):
    card_type: str
    card_last_digits: str
    card_first_digits: str

class ChargeCompleted(BaseModel):
    order_id: str
    amount: int
    status: str
    installments: int
    card_type: str
    card_last_digits: str
    card_first_digits: str
    created_at: str

class ChargeFuture(BaseModel):
    charge_date: str

class Charges(BaseModel):
    completed: List[ChargeCompleted]
    future: List[ChargeFuture]

class Plan(BaseModel):
    id: str
    name: str
    frequency: str
    qty_charges: int

class SubscriptionData(BaseModel):
    start_date: str
    next_payment: str
    status: str
    plan: Plan
    charges: Charges
    subscription_id: str
    access_url: Optional[str] = None

class SubscriptionWebhook(BaseModel):
    data: SubscriptionData
    webhookUrl: str
    executionMode: str 