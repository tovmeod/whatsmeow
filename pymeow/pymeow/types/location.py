"""
Location-related types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Union, Any, Tuple

from .jid import JID

class LocationAccuracy(int, Enum):
    """Accuracy levels for location data."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    MAXIMUM = 3

class LocationType(str, Enum):
    """Types of location data."""
    LOCATION = "location"
    LIVE = "live_location"
    PLACE = "place"
    VENUE = "venue"

@dataclass
class Coordinates:
    """Geographic coordinates (latitude and longitude)."""
    latitude: float
    longitude: float
    accuracy: Optional[float] = None  # in meters
    altitude: Optional[float] = None  # in meters
    speed: Optional[float] = None  # in m/s
    bearing: Optional[float] = None  # in degrees
    timestamp: Optional[datetime] = None
    
    def to_tuple(self) -> Tuple[float, float]:
        """Convert to a (latitude, longitude) tuple."""
        return (self.latitude, self.longitude)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'latitude': self.latitude,
            'longitude': self.longitude,
            'accuracy': self.accuracy,
            'altitude': self.altitude,
            'speed': self.speed,
            'bearing': self.bearing,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Coordinates':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            latitude=data['latitude'],
            longitude=data['longitude'],
            accuracy=data.get('accuracy'),
            altitude=data.get('altitude'),
            speed=data.get('speed'),
            bearing=data.get('bearing'),
            timestamp=datetime.fromisoformat(data['timestamp']) if data.get('timestamp') else None,
        )

@dataclass
class LocationInfo:
    """Information about a location."""
    coordinates: Coordinates
    name: Optional[str] = None
    address: Optional[str] = None
    url: Optional[str] = None
    type: LocationType = LocationType.LOCATION
    accuracy: LocationAccuracy = LocationAccuracy.MEDIUM
    speed: Optional[float] = None  # in m/s
    bearing: Optional[float] = None  # in degrees
    altitude: Optional[float] = None  # in meters
    timestamp: Optional[datetime] = None
    live_until: Optional[datetime] = None  # for live locations
    is_current: bool = False
    raw_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'coordinates': self.coordinates.to_dict(),
            'name': self.name,
            'address': self.address,
            'url': self.url,
            'type': self.type.value,
            'accuracy': self.accuracy.value,
            'speed': self.speed,
            'bearing': self.bearing,
            'altitude': self.altitude,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'live_until': self.live_until.isoformat() if self.live_until else None,
            'is_current': self.is_current,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LocationInfo':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            coordinates=Coordinates.from_dict(data['coordinates']),
            name=data.get('name'),
            address=data.get('address'),
            url=data.get('url'),
            type=LocationType(data.get('type', 'location')),
            accuracy=LocationAccuracy(data.get('accuracy', 1)),
            speed=data.get('speed'),
            bearing=data.get('bearing'),
            altitude=data.get('altitude'),
            timestamp=datetime.fromisoformat(data['timestamp']) if data.get('timestamp') else None,
            live_until=datetime.fromisoformat(data['live_until']) if data.get('live_until') else None,
            is_current=data.get('is_current', False),
            raw_data=data.get('raw_data'),
        )

@dataclass
class LiveLocationInfo(LocationInfo):
    """Information about a live location."""
    type: LocationType = LocationType.LIVE
    duration: Optional[int] = None  # in seconds
    is_expired: bool = False
    share_until: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        data = super().to_dict()
        data.update({
            'duration': self.duration,
            'is_expired': self.is_expired,
            'share_until': self.share_until.isoformat() if self.share_until else None,
        })
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LiveLocationInfo':
        """Create from a dictionary."""
        from datetime import datetime
        base = super().from_dict(data)
        return cls(
            coordinates=base.coordinates,
            name=base.name,
            address=base.address,
            url=base.url,
            type=LocationType.LIVE,
            accuracy=base.accuracy,
            speed=base.speed,
            bearing=base.bearing,
            altitude=base.altitude,
            timestamp=base.timestamp,
            live_until=base.live_until,
            is_current=base.is_current,
            raw_data=base.raw_data,
            duration=data.get('duration'),
            is_expired=data.get('is_expired', False),
            share_until=datetime.fromisoformat(data['share_until']) if data.get('share_until') else None,
        )

@dataclass
class PlaceInfo(LocationInfo):
    """Information about a place or venue."""
    type: LocationType = LocationType.PLACE
    place_id: Optional[str] = None
    place_name: Optional[str] = None
    place_address: Optional[str] = None
    place_url: Optional[str] = None
    place_rating: Optional[float] = None
    place_categories: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        data = super().to_dict()
        data.update({
            'place_id': self.place_id,
            'place_name': self.place_name,
            'place_address': self.place_address,
            'place_url': self.place_url,
            'place_rating': self.place_rating,
            'place_categories': self.place_categories,
        })
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PlaceInfo':
        """Create from a dictionary."""
        base = super().from_dict(data)
        return cls(
            coordinates=base.coordinates,
            name=base.name,
            address=base.address,
            url=base.url,
            type=LocationType.PLACE,
            accuracy=base.accuracy,
            speed=base.speed,
            bearing=base.bearing,
            altitude=base.altitude,
            timestamp=base.timestamp,
            live_until=base.live_until,
            is_current=base.is_current,
            raw_data=base.raw_data,
            place_id=data.get('place_id'),
            place_name=data.get('place_name'),
            place_address=data.get('place_address'),
            place_url=data.get('place_url'),
            place_rating=data.get('place_rating'),
            place_categories=data.get('place_categories', []),
        )

@dataclass
class VenueInfo(PlaceInfo):
    """Information about a venue (extends PlaceInfo)."""
    type: LocationType = LocationType.VENUE
    venue_id: Optional[str] = None
    venue_type: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        data = super().to_dict()
        data.update({
            'venue_id': self.venue_id,
            'venue_type': self.venue_type,
        })
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VenueInfo':
        """Create from a dictionary."""
        base = super().from_dict(data)
        return cls(
            coordinates=base.coordinates,
            name=base.name,
            address=base.address,
            url=base.url,
            type=LocationType.VENUE,
            accuracy=base.accuracy,
            speed=base.speed,
            bearing=base.bearing,
            altitude=base.altitude,
            timestamp=base.timestamp,
            live_until=base.live_until,
            is_current=base.is_current,
            raw_data=base.raw_data,
            place_id=base.place_id,
            place_name=base.place_name,
            place_address=base.place_address,
            place_url=base.place_url,
            place_rating=base.place_rating,
            place_categories=base.place_categories,
            venue_id=data.get('venue_id'),
            venue_type=data.get('venue_type'),
        )
