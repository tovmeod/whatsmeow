"""
Business account related types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime, time
from enum import Enum
from typing import Dict, List, Optional, Union, Any, Tuple

from .jid import JID

class BusinessCategory(str, Enum):
    """Main categories for business accounts."""
    UNDEFINED = "UNDEFINED"
    ACCOUNTING = "ACCOUNTING"
    AIRLINES = "AIRLINES"
    AUTOMOTIVE = "AUTOMOTIVE"
    BANKING = "BANKING"
    BEAUTY = "BEAUTY"
    BUSINESS = "BUSINESS"
    CONSTRUCTION = "CONSTRUCTION"
    CONSULTING = "CONSULTING"
    EDUCATION = "EDUCATION"
    ENTERTAINMENT = "ENTERTAINMENT"
    FINANCIAL_SERVICES = "FINANCIAL_SERVICES"
    FOOD_BEVERAGE = "FOOD_BEVERAGE"
    GOVERNMENT = "GOVERNMENT"
    HEALTH = "HEALTH"
    HOSPITALITY = "HOSPITALITY"
    INSURANCE = "INSURANCE"
    JEWELRY = "JEWELRY"
    LEGAL = "LEGAL"
    LIFESTYLE = "LIFESTYLE"
    MARKETING = "MARKETING"
    MEDICAL = "MEDICAL"
    NONPROFIT = "NONPROFIT"
    PROFESSIONAL_SERVICES = "PROFESSIONAL_SERVICES"
    REAL_ESTATE = "REAL_ESTATE"
    RETAIL = "RETAIL"
    TECHNOLOGY = "TECHNOLOGY"
    TELECOMMUNICATIONS = "TELECOMMUNICATIONS"
    TRAVEL = "TRAVEL"
    OTHER = "OTHER"

class BusinessHoursDay(str, Enum):
    """Days of the week for business hours."""
    MONDAY = "monday"
    TUESDAY = "tuesday"
    WEDNESDAY = "wednesday"
    THURSDAY = "thursday"
    FRIDAY = "friday"
    SATURDAY = "saturday"
    SUNDAY = "sunday"

@dataclass
class BusinessHoursTime:
    """Represents a time of day in 24-hour format."""
    hour: int  # 0-23
    minute: int  # 0-59
    
    def __post_init__(self):
        if not 0 <= self.hour <= 23:
            raise ValueError("Hour must be between 0 and 23")
        if not 0 <= self.minute <= 59:
            raise ValueError("Minute must be between 0 and 59")
    
    def to_string(self) -> str:
        """Convert to HH:MM format string."""
        return f"{self.hour:02d}:{self.minute:02d}"
    
    @classmethod
    def from_string(cls, time_str: str) -> 'BusinessHoursTime':
        """Create from HH:MM format string."""
        try:
            hour_str, minute_str = time_str.split(':')
            return cls(hour=int(hour_str), minute=int(minute_str))
        except (ValueError, AttributeError) as e:
            raise ValueError("Time must be in HH:MM format") from e
    
    def to_dict(self) -> Dict[str, int]:
        """Convert to a dictionary."""
        return {'hour': self.hour, 'minute': self.minute}
    
    @classmethod
    def from_dict(cls, data: Dict[str, int]) -> 'BusinessHoursTime':
        """Create from a dictionary."""
        return cls(hour=data['hour'], minute=data['minute'])

@dataclass
class BusinessHoursRange:
    """Represents a time range for business hours."""
    open_time: BusinessHoursTime
    close_time: BusinessHoursTime
    
    def is_open_now(self) -> bool:
        """Check if the current time is within this range."""
        now = datetime.now().time()
        current = now.hour * 60 + now.minute
        open_minutes = self.open_time.hour * 60 + self.open_time.minute
        close_minutes = self.close_time.hour * 60 + self.close_time.minute
        return open_minutes <= current < close_minutes
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        return {
            'open_time': self.open_time.to_dict(),
            'close_time': self.close_time.to_dict()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BusinessHoursRange':
        """Create from a dictionary."""
        return cls(
            open_time=BusinessHoursTime.from_dict(data['open_time']),
            close_time=BusinessHoursTime.from_dict(data['close_time'])
        )

@dataclass
class BusinessHoursSchedule:
    """Business hours schedule for a single day."""
    day: BusinessHoursDay
    is_closed: bool = True
    time_ranges: List[BusinessHoursRange] = field(default_factory=list)
    
    def is_open_now(self) -> bool:
        """Check if the business is open now."""
        if self.is_closed or not self.time_ranges:
            return False
        
        # Get current day of week (0=Monday, 6=Sunday)
        current_weekday = datetime.now().weekday()
        target_weekday = list(BusinessHoursDay).index(self.day)
        
        # If not today, not open
        if current_weekday != target_weekday:
            return False
            
        # Check if current time is within any time range
        current_time = datetime.now().time()
        for time_range in self.time_ranges:
            if time_range.is_open_now():
                return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        return {
            'day': self.day.value,
            'is_closed': self.is_closed,
            'time_ranges': [tr.to_dict() for tr in self.time_ranges]
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BusinessHoursSchedule':
        """Create from a dictionary."""
        return cls(
            day=BusinessHoursDay(data['day']),
            is_closed=data.get('is_closed', True),
            time_ranges=[BusinessHoursRange.from_dict(tr) for tr in data.get('time_ranges', [])]
        )

@dataclass
class BusinessProfile:
    """Business profile information."""
    business_jid: JID
    name: str
    description: Optional[str] = None
    email: Optional[str] = None
    website: Optional[str] = None
    address: Optional[str] = None
    category: BusinessCategory = BusinessCategory.UNDEFINED
    subcategory: Optional[str] = None
    business_hours: List[BusinessHoursSchedule] = field(default_factory=list)
    timezone: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    verified: bool = False
    is_profile_public: bool = True
    is_messaging_enabled: bool = True
    
    def is_open_now(self) -> bool:
        """Check if the business is currently open."""
        if not self.business_hours:
            return False
            
        # Get current day of week (0=Monday, 6=Sunday)
        current_weekday = datetime.now().weekday()
        day_name = list(BusinessHoursDay)[current_weekday].value
        
        # Find today's schedule
        today_schedule = next(
            (sched for sched in self.business_hours if sched.day.value == day_name),
            None
        )
        
        if not today_schedule:
            return False
            
        return today_schedule.is_open_now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'business_jid': str(self.business_jid),
            'name': self.name,
            'description': self.description,
            'email': self.email,
            'website': self.website,
            'address': self.address,
            'category': self.category.value,
            'subcategory': self.subcategory,
            'business_hours': [bh.to_dict() for bh in self.business_hours],
            'timezone': self.timezone,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'verified': self.verified,
            'is_profile_public': self.is_profile_public,
            'is_messaging_enabled': self.is_messaging_enabled,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BusinessProfile':
        """Create from a dictionary."""
        return cls(
            business_jid=JID.from_string(data['business_jid']),
            name=data['name'],
            description=data.get('description'),
            email=data.get('email'),
            website=data.get('website'),
            address=data.get('address'),
            category=BusinessCategory(data.get('category', 'UNDEFINED')),
            subcategory=data.get('subcategory'),
            business_hours=[
                BusinessHoursSchedule.from_dict(bh) 
                for bh in data.get('business_hours', [])
            ],
            timezone=data.get('timezone'),
            latitude=data.get('latitude'),
            longitude=data.get('longitude'),
            verified=data.get('verified', False),
            is_profile_public=data.get('is_profile_public', True),
            is_messaging_enabled=data.get('is_messaging_enabled', True),
        )
