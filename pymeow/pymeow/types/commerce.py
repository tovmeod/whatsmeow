"""
Commerce and catalog related types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any, Literal

from .jid import JID

class CurrencyCode(str, Enum):
    """Supported currency codes for product pricing."""
    AED = "AED"  # UAE Dirham
    ARS = "ARS"  # Argentine Peso
    AUD = "AUD"  # Australian Dollar
    BDT = "BDT"  # Bangladeshi Taka
    BOB = "BOB"  # Bolivian Boliviano
    BRL = "BRL"  # Brazilian Real
    CAD = "CAD"  # Canadian Dollar
    CHF = "CHF"  # Swiss Franc
    CLP = "CLP"  # Chilean Peso
    CNY = "CNY"  # Chinese Yuan
    COP = "COP"  # Colombian Peso
    CRC = "CRC"  # Costa Rican Colón
    CZK = "CZK"  # Czech Koruna
    DKK = "DKK"  # Danish Krone
    DOP = "DOP"  # Dominican Peso
    EGP = "EGP"  # Egyptian Pound
    EUR = "EUR"  # Euro
    GBP = "GBP"  # British Pound
    GTQ = "GTQ"  # Guatemalan Quetzal
    HKD = "HKD"  # Hong Kong Dollar
    HNL = "HNL"  # Honduran Lempira
    HUF = "HUF"  # Hungarian Forint
    IDR = "IDR"  # Indonesian Rupiah
    ILS = "ILS"  # Israeli New Shekel
    INR = "INR"  # Indian Rupee
    JMD = "JMD"  # Jamaican Dollar
    JPY = "JPY"  # Japanese Yen
    KRW = "KRW"  # South Korean Won
    MXN = "MXN"  # Mexican Peso
    MYR = "MYR"  # Malaysian Ringgit
    NGN = "NGN"  # Nigerian Naira
    NIO = "NIO"  # Nicaraguan Córdoba
    NOK = "NOK"  # Norwegian Krone
    NZD = "NZD"  # New Zealand Dollar
    PEN = "PEN"  # Peruvian Sol
    PHP = "PHP"  # Philippine Peso
    PKR = "PKR"  # Pakistani Rupee
    PLN = "PLN"  # Polish Złoty
    PYG = "PYG"  # Paraguayan Guaraní
    QAR = "QAR"  # Qatari Riyal
    RON = "RON"  # Romanian Leu
    RUB = "RUB"  # Russian Ruble
    SAR = "SAR"  # Saudi Riyal
    SEK = "SEK"  # Swedish Krona
    SGD = "SGD"  # Singapore Dollar
    THB = "THB"  # Thai Baht
    TRY = "TRY"  # Turkish Lira
    TWD = "TWD"  # New Taiwan Dollar
    UAH = "UAH"  # Ukrainian Hryvnia
    USD = "USD"  # US Dollar
    UYU = "UYU"  # Uruguayan Peso
    VEF = "VEF"  # Venezuelan Bolívar
    VND = "VND"  # Vietnamese Đồng
    ZAR = "ZAR"  # South African Rand

class ProductAvailability(str, Enum):
    """Product availability status."""
    IN_STOCK = "in_stock"
    OUT_OF_STOCK = "out_of_stock"
    PREORDER = "preorder"
    AVAILABLE = "available"
    LOW_STOCK = "low_stock"

class ProductCondition(str, Enum):
    """Product condition."""
    NEW = "new"
    REFURBISHED = "refurbished"
    USED_GOOD = "used_good"
    USED_FAIR = "used_fair"
    USED_LIKE_NEW = "used_like_new"

class ProductPrice:
    """Product price information."""
    def __init__(
        self,
        amount: Union[int, float, str],
        currency: Union[CurrencyCode, str],
    ):
        self.amount = float(amount) if amount else 0.0
        self.currency = CurrencyCode(currency) if isinstance(currency, str) else currency
    
    def __str__(self) -> str:
        return f"{self.currency.value} {self.amount:.2f}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        return {
            'amount': str(self.amount),
            'currency': self.currency.value,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProductPrice':
        """Create from a dictionary."""
        return cls(
            amount=data.get('amount', 0),
            currency=data.get('currency', 'USD'),
        )

@dataclass
class ProductImage:
    """Product image information."""
    id: str
    url: str
    width: Optional[int] = None
    height: Optional[int] = None
    caption: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        return {
            'id': self.id,
            'url': self.url,
            'width': self.width,
            'height': self.height,
            'caption': self.caption,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProductImage':
        """Create from a dictionary."""
        return cls(
            id=data['id'],
            url=data['url'],
            width=data.get('width'),
            height=data.get('height'),
            caption=data.get('caption'),
        )

@dataclass
class ProductVariant:
    """Product variant information."""
    name: str
    value: str
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to a dictionary."""
        return {
            'name': self.name,
            'value': self.value,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'ProductVariant':
        """Create from a dictionary."""
        return cls(
            name=data['name'],
            value=data['value'],
        )

@dataclass
class Product:
    """Product information for WhatsApp Business catalog."""
    id: str
    name: str
    retailer_id: Optional[str] = None
    description: Optional[str] = None
    price: Optional[ProductPrice] = None
    currency: Optional[Union[CurrencyCode, str]] = None
    is_hidden: bool = False
    images: List[ProductImage] = field(default_factory=list)
    url: Optional[str] = None
    variants: List[ProductVariant] = field(default_factory=list)
    review_status: Optional[str] = None
    availability: ProductAvailability = ProductAvailability.IN_STOCK
    condition: Optional[ProductCondition] = None
    sku: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def __post_init__(self):
        # For backward compatibility, if price is not provided but currency is
        if self.price is None and self.currency is not None:
            self.price = ProductPrice(0, self.currency)
    
    @property
    def primary_image(self) -> Optional[ProductImage]:
        """Get the primary product image."""
        return self.images[0] if self.images else None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for API requests."""
        data = {
            'id': self.id,
            'retailer_id': self.retailer_id or self.id,
            'name': self.name,
            'is_hidden': self.is_hidden,
            'review_status': self.review_status,
            'availability': self.availability.value,
        }
        
        if self.description:
            data['description'] = self.description
        if self.price:
            data['price'] = self.price.to_dict()
        if self.currency and not self.price:
            data['currency'] = self.currency.value if hasattr(self.currency, 'value') else self.currency
        if self.url:
            data['url'] = self.url
        if self.condition:
            data['condition'] = self.condition.value
        if self.sku:
            data['sku'] = self.sku
        if self.images:
            data['image_url'] = self.images[0].url
        if self.variants:
            data['variants'] = [v.to_dict() for v in self.variants]
        if self.created_at:
            data['created_at'] = self.created_at.isoformat()
        if self.updated_at:
            data['updated_at'] = self.updated_at.isoformat()
            
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Product':
        """Create from a dictionary."""
        price_data = data.get('price', {})
        price = None
        
        if price_data:
            price = ProductPrice(
                amount=price_data.get('amount', 0),
                currency=price_data.get('currency', 'USD'),
            )
        
        images = []
        if 'image_url' in data:
            images.append(ProductImage(
                id='0',
                url=data['image_url'],
            ))
        elif 'images' in data:
            images = [ProductImage.from_dict(img) for img in data['images']]
        
        created_at = (
            datetime.fromisoformat(data['created_at'])
            if 'created_at' in data and data['created_at']
            else None
        )
        
        updated_at = (
            datetime.fromisoformat(data['updated_at'])
            if 'updated_at' in data and data['updated_at']
            else None
        )
        
        return cls(
            id=data['id'],
            retailer_id=data.get('retailer_id', data.get('id')),
            name=data['name'],
            description=data.get('description'),
            price=price,
            currency=data.get('currency'),
            is_hidden=data.get('is_hidden', False),
            images=images,
            url=data.get('url'),
            variants=[
                ProductVariant.from_dict(v) 
                for v in data.get('variants', [])
            ],
            review_status=data.get('review_status'),
            availability=ProductAvailability(data.get('availability', 'in_stock')),
            condition=ProductCondition(data['condition']) if 'condition' in data else None,
            sku=data.get('sku'),
            created_at=created_at,
            updated_at=updated_at,
        )

@dataclass
class Catalog:
    """A business catalog containing products."""
    id: str
    name: str
    business_owner_id: str
    products: List[Product] = field(default_factory=list)
    is_default: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'business_owner_id': self.business_owner_id,
            'is_default': self.is_default,
            'products': [p.to_dict() for p in self.products],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Catalog':
        """Create from a dictionary."""
        created_at = (
            datetime.fromisoformat(data['created_at'])
            if 'created_at' in data and data['created_at']
            else None
        )
        
        updated_at = (
            datetime.fromisoformat(data['updated_at'])
            if 'updated_at' in data and data['updated_at']
            else None
        )
        
        return cls(
            id=data['id'],
            name=data['name'],
            business_owner_id=data['business_owner_id'],
            is_default=data.get('is_default', False),
            products=[
                Product.from_dict(p) 
                for p in data.get('products', [])
            ],
            created_at=created_at,
            updated_at=updated_at,
        )

@dataclass
class CartItem:
    """An item in a shopping cart."""
    product_id: str
    quantity: int
    item_price: Optional[ProductPrice] = None
    variants: List[ProductVariant] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        data = {
            'product_id': self.product_id,
            'quantity': str(self.quantity),
        }
        
        if self.item_price:
            data['item_price'] = self.item_price.to_dict()
        if self.variants:
            data['variants'] = [v.to_dict() for v in self.variants]
            
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CartItem':
        """Create from a dictionary."""
        item_price_data = data.get('item_price', {})
        item_price = None
        
        if item_price_data:
            item_price = ProductPrice(
                amount=item_price_data.get('amount', 0),
                currency=item_price_data.get('currency', 'USD'),
            )
        
        return cls(
            product_id=data['product_id'],
            quantity=int(data.get('quantity', 1)),
            item_price=item_price,
            variants=[
                ProductVariant.from_dict(v) 
                for v in data.get('variants', [])
            ],
        )

@dataclass
class Cart:
    """A shopping cart for WhatsApp Business orders."""
    id: str
    items: List[CartItem] = field(default_factory=list)
    subtotal: Optional[ProductPrice] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def add_item(self, item: CartItem) -> None:
        """Add an item to the cart."""
        self.items.append(item)
    
    def remove_item(self, product_id: str) -> bool:
        """Remove an item from the cart by product ID."""
        initial_count = len(self.items)
        self.items = [item for item in self.items if item.product_id != product_id]
        return len(self.items) < initial_count
    
    def get_item(self, product_id: str) -> Optional[CartItem]:
        """Get an item by product ID."""
        for item in self.items:
            if item.product_id == product_id:
                return item
        return None
    
    def update_quantity(self, product_id: str, quantity: int) -> bool:
        """Update the quantity of an item in the cart."""
        for item in self.items:
            if item.product_id == product_id:
                item.quantity = quantity
                return True
        return False
    
    def clear(self) -> None:
        """Remove all items from the cart."""
        self.items = []
    
    @property
    def total_items(self) -> int:
        """Get the total number of items in the cart."""
        return sum(item.quantity for item in self.items)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        data = {
            'id': self.id,
            'items': [item.to_dict() for item in self.items],
        }
        
        if self.subtotal:
            data['subtotal'] = self.subtotal.to_dict()
        if self.created_at:
            data['created_at'] = self.created_at.isoformat()
        if self.updated_at:
            data['updated_at'] = self.updated_at.isoformat()
            
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Cart':
        """Create from a dictionary."""
        subtotal_data = data.get('subtotal', {})
        subtotal = None
        
        if subtotal_data:
            subtotal = ProductPrice(
                amount=subtotal_data.get('amount', 0),
                currency=subtotal_data.get('currency', 'USD'),
            )
        
        created_at = (
            datetime.fromisoformat(data['created_at'])
            if 'created_at' in data and data['created_at']
            else None
        )
        
        updated_at = (
            datetime.fromisoformat(data['updated_at'])
            if 'updated_at' in data and data['updated_at']
            else None
        )
        
        return cls(
            id=data['id'],
            items=[CartItem.from_dict(item) for item in data.get('items', [])],
            subtotal=subtotal,
            created_at=created_at,
            updated_at=updated_at,
        )
