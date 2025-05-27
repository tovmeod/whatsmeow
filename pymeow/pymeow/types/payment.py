"""
Payment-related types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Union, Any

from .jid import JID

class PaymentCurrency(str, Enum):
    """Supported payment currencies."""
    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"
    BRL = "BRL"
    INR = "INR"
    IDR = "IDR"
    MXN = "MXN"
    TRY = "TRY"
    
class PaymentStatus(str, Enum):
    """Status of a payment."""
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REFUNDED = "REFUNDED"
    DECLINED = "DECLINED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"

class PaymentMethodType(str, Enum):
    """Types of payment methods."""
    CREDIT_CARD = "CREDIT_CARD"
    DEBIT_CARD = "DEBIT_CARD"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    UPI = "UPI"  # For India
    PAYTM = "PAYTM"  # For India
    GO_PAY = "GO_PAY"  # For Indonesia
    OVO = "OVO"  # For Indonesia
    DANA = "DANA"  # For Indonesia
    
@dataclass
class Money:
    """Represents an amount of money with currency."""
    value: float
    currency: PaymentCurrency
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'value': self.value,
            'currency': self.currency.value,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Money':
        """Create from a dictionary."""
        return cls(
            value=float(data['value']),
            currency=PaymentCurrency(data['currency']),
        )

@dataclass
class PaymentMethod:
    """Information about a payment method."""
    method_type: PaymentMethodType
    last_four: Optional[str] = None
    expiry_month: Optional[int] = None
    expiry_year: Optional[int] = None
    bank_name: Optional[str] = None
    bank_code: Optional[str] = None
    vpa: Optional[str] = None  # Virtual Payment Address (for UPI)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'method_type': self.method_type.value,
            'last_four': self.last_four,
            'expiry_month': self.expiry_month,
            'expiry_year': self.expiry_year,
            'bank_name': self.bank_name,
            'bank_code': self.bank_code,
            'vpa': self.vpa,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PaymentMethod':
        """Create from a dictionary."""
        return cls(
            method_type=PaymentMethodType(data['method_type']),
            last_four=data.get('last_four'),
            expiry_month=data.get('expiry_month'),
            expiry_year=data.get('expiry_year'),
            bank_name=data.get('bank_name'),
            bank_code=data.get('bank_code'),
            vpa=data.get('vpa'),
        )

@dataclass
class PaymentInfo:
    """Information about a payment."""
    transaction_id: str
    amount: Money
    status: PaymentStatus
    timestamp: datetime
    sender_jid: JID
    recipient_jid: JID
    note: Optional[str] = None
    payment_method: Optional[PaymentMethod] = None
    fee: Optional[Money] = None
    tax: Optional[Money] = None
    reference_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'transaction_id': self.transaction_id,
            'amount': self.amount.to_dict(),
            'status': self.status.value,
            'timestamp': self.timestamp.isoformat(),
            'sender_jid': str(self.sender_jid),
            'recipient_jid': str(self.recipient_jid),
            'note': self.note,
            'payment_method': self.payment_method.to_dict() if self.payment_method else None,
            'fee': self.fee.to_dict() if self.fee else None,
            'tax': self.tax.to_dict() if self.tax else None,
            'reference_id': self.reference_id,
            'metadata': self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PaymentInfo':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            transaction_id=data['transaction_id'],
            amount=Money.from_dict(data['amount']),
            status=PaymentStatus(data['status']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            sender_jid=JID.from_string(data['sender_jid']),
            recipient_jid=JID.from_string(data['recipient_jid']),
            note=data.get('note'),
            payment_method=PaymentMethod.from_dict(data['payment_method']) if data.get('payment_method') else None,
            fee=Money.from_dict(data['fee']) if data.get('fee') else None,
            tax=Money.from_dict(data['tax']) if data.get('tax') else None,
            reference_id=data.get('reference_id'),
            metadata=data.get('metadata', {}),
        )

@dataclass
class PaymentRequest:
    """A request for payment from one user to another."""
    request_id: str
    amount: Money
    sender_jid: JID
    recipient_jid: JID
    timestamp: datetime
    expiry: Optional[datetime] = None
    note: Optional[str] = None
    status: PaymentStatus = PaymentStatus.PENDING
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'request_id': self.request_id,
            'amount': self.amount.to_dict(),
            'sender_jid': str(self.sender_jid),
            'recipient_jid': str(self.recipient_jid),
            'timestamp': self.timestamp.isoformat(),
            'expiry': self.expiry.isoformat() if self.expiry else None,
            'note': self.note,
            'status': self.status.value,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PaymentRequest':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            request_id=data['request_id'],
            amount=Money.from_dict(data['amount']),
            sender_jid=JID.from_string(data['sender_jid']),
            recipient_jid=JID.from_string(data['recipient_jid']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            expiry=datetime.fromisoformat(data['expiry']) if data.get('expiry') else None,
            note=data.get('note'),
            status=PaymentStatus(data.get('status', 'PENDING')),
        )
